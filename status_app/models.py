import uuid
from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from django.utils.text import slugify


class Organization(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100, db_index=True)
    slug = models.SlugField(max_length=100, unique=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    owner = models.ForeignKey(
        User,
        on_delete=models.PROTECT,
        related_name='owned_organizations',
        null=True,  # Allow null for existing organizations
        blank=True  # Allow blank in forms
    )
    members = models.ManyToManyField(
        User, through='OrganizationMembership', related_name='organizations')

    class Meta:
        indexes = [
            models.Index(fields=['name', 'created_at']),
        ]

    def __str__(self):
        return self.name


class OrganizationMembership(models.Model):
    ROLE_CHOICES = [
        ('owner', 'Owner'),
        ('admin', 'Admin'),
        ('member', 'Member'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE)
    role = models.CharField(
        max_length=20, choices=ROLE_CHOICES, default='member')
    joined_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('user', 'organization')

    def __str__(self):
        return f"{self.user.username} - {self.organization.name} ({self.role})"


class Invitation(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField()
    organization = models.ForeignKey(
        Organization, on_delete=models.CASCADE, related_name='invitations')
    inviter = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='sent_invitations')
    created_at = models.DateTimeField(auto_now_add=True)
    accepted = models.BooleanField(default=False)

    def __str__(self):
        return f"Invitation for {self.email} to join {self.organization.name}"


class Team(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100, db_index=True)
    slug = models.SlugField(max_length=100)
    organization = models.ForeignKey(
        Organization, on_delete=models.CASCADE, related_name='teams')
    members = models.ManyToManyField(
        User, through='TeamMembership', related_name='team_memberships')

    class Meta:
        indexes = [
            models.Index(fields=['name', 'organization']),
        ]
        unique_together = ['organization', 'slug']

    def __str__(self):
        return f"{self.name} ({self.organization.name})"


class TeamMembership(models.Model):
    ROLE_CHOICES = [
        ('lead', 'Team Lead'),
        ('member', 'Team Member'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    team = models.ForeignKey(Team, on_delete=models.CASCADE)
    role = models.CharField(
        max_length=20, choices=ROLE_CHOICES, default='member')
    joined_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('user', 'team')

    def __str__(self):
        return f"{self.user.username} - {self.team.name} ({self.role})"


class Service(models.Model):
    STATUS_CHOICES = [
        ('operational', 'Operational'),
        ('degraded', 'Degraded Performance'),
        ('partial', 'Partial Outage'),
        ('major', 'Major Outage'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100, db_index=True)
    slug = models.SlugField(max_length=100)
    description = models.TextField(blank=True)
    status = models.CharField(
        max_length=20, choices=STATUS_CHOICES, default='operational', db_index=True)
    organization = models.ForeignKey(
        'Organization', on_delete=models.CASCADE, related_name='services')
    team = models.ForeignKey(
        'Team', on_delete=models.SET_NULL, null=True, blank=True, related_name='services')

    class Meta:
        indexes = [
            models.Index(fields=['name', 'status', 'organization']),
        ]
        unique_together = ['organization', 'slug']

    def save(self, *args, **kwargs):
        if not self.slug:
            self.slug = slugify(self.name)
            # Check for existing services with the same slug in the organization
            existing_services = Service.objects.filter(
                organization=self.organization, slug=self.slug)
            if existing_services.exists():
                # If a service with this slug exists, append a number to make it unique
                count = existing_services.count()
                while Service.objects.filter(organization=self.organization, slug=f"{self.slug}-{count+1}").exists():
                    count += 1
                self.slug = f"{self.slug}-{count+1}"
        super().save(*args, **kwargs)

    def __str__(self):
        team_name = self.team.name if self.team else "No Team"
        return f"{self.name} ({self.get_status_display()}) - {team_name}"


class Incident(models.Model):
    SEVERITY_CHOICES = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]

    STATUS_CHOICES = [
        ('investigating', 'Investigating'),
        ('identified', 'Identified'),
        ('monitoring', 'Monitoring'),
        ('resolved', 'Resolved'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    title = models.CharField(max_length=200, db_index=True)
    description = models.TextField()
    services = models.ManyToManyField(Service, related_name='incidents')
    severity = models.CharField(
        max_length=20, choices=SEVERITY_CHOICES, db_index=True)
    started_at = models.DateTimeField(db_index=True, default=timezone.now)
    status = models.CharField(
        max_length=20, choices=STATUS_CHOICES, default='investigating', db_index=True)
    last_update = models.DateTimeField(default=timezone.now, db_index=True)
    resolved_at = models.DateTimeField(null=True, blank=True, db_index=True)
    organization = models.ForeignKey(
        Organization, on_delete=models.CASCADE, related_name='incidents')

    class Meta:
        indexes = [
            models.Index(fields=['title', 'severity', 'started_at',
                         'resolved_at', 'last_update', 'organization']),
        ]

    def __str__(self):
        return f"{self.title} ({self.get_severity_display()})"

    def save(self, *args, **kwargs):
        if not self.id:
            # This is a new instance, set started_at to current time
            self.started_at = timezone.now()

        # Update last_update when the incident is saved
        self.last_update = timezone.now()
        super().save(*args, **kwargs)


class IncidentUpdate(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    incident = models.ForeignKey(
        Incident, on_delete=models.CASCADE, related_name='updates')
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        indexes = [
            models.Index(fields=['incident', 'created_at']),
        ]

    def __str__(self):
        return f"Update for {self.incident.title} at {self.created_at}"


class Maintenance(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    title = models.CharField(max_length=200, db_index=True)
    description = models.TextField()
    services = models.ManyToManyField(Service, related_name='maintenances')
    scheduled_start = models.DateTimeField(db_index=True)
    scheduled_end = models.DateTimeField(db_index=True)
    organization = models.ForeignKey(
        Organization, on_delete=models.CASCADE, related_name='maintenances')

    class Meta:
        indexes = [
            models.Index(fields=['title', 'scheduled_start',
                         'scheduled_end', 'organization']),
        ]

    def __str__(self):
        return f"{self.title} ({self.scheduled_start} - {self.scheduled_end})"
