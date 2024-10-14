# status_app/serializers.py

from .models import Team, Organization
from django.db import IntegrityError
from rest_framework import serializers
from django.utils import timezone
from django.utils.timezone import is_aware, make_aware

from .models import Organization, Team, Service, Incident, IncidentUpdate, Maintenance, OrganizationMembership
from django.contrib.auth.models import User


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email']


class OrganizationSerializer(serializers.ModelSerializer):
    owner = serializers.ReadOnlyField(source='owner.username')

    class Meta:
        model = Organization
        fields = ['id', 'name', 'slug', 'owner', 'created_at']
        read_only_fields = ['id', 'owner', 'created_at']

    def create(self, validated_data):
        # The 'owner' will be set in the ViewSet's create method
        return Organization.objects.create(**validated_data)


class OrganizationDetailSerializer(serializers.ModelSerializer):
    owner = serializers.ReadOnlyField(source='owner.username')
    members = serializers.SerializerMethodField()

    class Meta:
        model = Organization
        fields = ['id', 'name', 'slug', 'owner', 'created_at', 'members']
        read_only_fields = ['id', 'owner', 'created_at', 'members']

    def get_members(self, obj):
        memberships = OrganizationMembership.objects.filter(
            organization=obj).select_related('user')
        members = []
        for membership in memberships:
            member_data = UserSerializer(membership.user).data
            member_data['role'] = membership.role
            member_data['teams'] = TeamSerializer(
                membership.user.team_memberships.filter(organization=obj), many=True).data
            members.append(member_data)
        return members


class TeamSerializer(serializers.ModelSerializer):
    members = UserSerializer(many=True, read_only=True)

    class Meta:
        model = Team
        fields = ['id', 'name', 'slug', 'organization', 'members']
        read_only_fields = ['organization', 'members']

    def validate(self, data):
        organization_id = self.context['view'].kwargs.get('organization_pk')
        slug = data.get('slug')

        if Team.objects.filter(organization_id=organization_id, slug=slug).exists():
            raise serializers.ValidationError(
                {"slug": "A team with this slug already exists in this organization."})

        return data

    def create(self, validated_data):
        try:
            return super().create(validated_data)
        except IntegrityError:
            raise serializers.ValidationError(
                {"slug": "A team with this slug already exists in this organization."})

    def to_representation(self, instance):
        representation = super().to_representation(instance)
        representation['member_count'] = instance.members.count()
        return representation


class ServiceSerializer(serializers.ModelSerializer):
    status_display = serializers.SerializerMethodField()

    class Meta:
        model = Service
        fields = ['id', 'name', 'slug', 'description',
                  'status', 'status_display', 'organization', 'team']
        read_only_fields = ['id', 'organization', 'status_display']

    def get_status_display(self, obj):
        return obj.get_status_display()

    def update(self, instance, validated_data):
        instance.name = validated_data.get('name', instance.name)
        instance.slug = validated_data.get('slug', instance.slug)
        instance.description = validated_data.get(
            'description', instance.description)
        instance.status = validated_data.get('status', instance.status)
        instance.team = validated_data.get('team', instance.team)
        instance.save()
        return instance


class ServiceCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Service
        fields = ['name', 'description']

    def create(self, validated_data):
        team = validated_data.pop('team')
        organization = validated_data.pop('organization')
        service = Service.objects.create(
            team=team, organization=organization, **validated_data)
        return service


class IncidentUpdateSerializer(serializers.ModelSerializer):
    incident_id = serializers.UUIDField(read_only=True)
    incident_title = serializers.CharField(
        source='incident.title', read_only=True)

    class Meta:
        model = IncidentUpdate
        fields = ['id', 'incident_id',
                  'incident_title', 'content', 'created_at']
        read_only_fields = ['id', 'incident_id',
                            'incident_title', 'created_at']

    def create(self, validated_data):
        incident = self.context.get('incident')
        if not incident:
            raise serializers.ValidationError(
                "Incident is required for creating an update.")

        update = IncidentUpdate.objects.create(
            incident=incident, **validated_data)

        # Update the incident's last_update field
        incident.last_update = timezone.now()
        incident.save(update_fields=['last_update'])

        return update

    def update(self, instance, validated_data):
        instance.content = validated_data.get('content', instance.content)
        instance.save()

        # Update the incident's last_update field
        instance.incident.last_update = timezone.now()
        instance.incident.save(update_fields=['last_update'])

        return instance


class IncidentSerializer(serializers.ModelSerializer):
    services = ServiceSerializer(many=True, read_only=True)
    service_ids = serializers.PrimaryKeyRelatedField(
        many=True, queryset=Service.objects.all(), write_only=True, required=False
    )
    updates = IncidentUpdateSerializer(many=True, read_only=True)

    class Meta:
        model = Incident
        fields = ['id', 'title', 'description', 'services', 'service_ids', 'status',
                  'severity', 'started_at', 'resolved_at', 'last_update', 'organization', 'updates']
        read_only_fields = ['organization', 'last_update', 'resolved_at']

    def validate(self, data):
        started_at = data.get('started_at') or (
            self.instance.started_at if self.instance else None)
        status = data.get('status')

        if status == 'resolved':
            resolved_at = timezone.now()
            if started_at and resolved_at < started_at:
                raise serializers.ValidationError(
                    {"status": "Resolution time cannot be earlier than the start time."}
                )

        return data

    def update_service_status(self, services, severity, is_resolved=False):
        for service in services:
            if is_resolved:
                service.status = 'operational'
            else:
                if severity == 'critical':
                    service.status = 'major_outage'
                elif severity == 'high':
                    service.status = 'partial_outage'
                elif severity == 'medium':
                    service.status = 'degraded_performance'
                else:  # low severity
                    service.status = 'degraded_performance'
            service.save()

    def create(self, validated_data):
        service_ids = validated_data.pop('service_ids', [])
        incident = Incident.objects.create(**validated_data)
        incident.services.set(service_ids)
        self.update_service_status(
            incident.services.all(), validated_data.get('severity'))
        return incident

    def update(self, instance, validated_data):
        service_ids = validated_data.pop('service_ids', None)

        new_status = validated_data.get('status')
        if new_status == 'resolved' and instance.status != 'resolved':
            validated_data['resolved_at'] = timezone.now()
            is_resolved = True
        else:
            is_resolved = False

        instance = super().update(instance, validated_data)

        if service_ids is not None:
            instance.services.set(service_ids)

        instance.last_update = timezone.now()
        instance.save()

        services_to_update = instance.services.all()
        if services_to_update or 'severity' in validated_data or is_resolved:
            self.update_service_status(
                services_to_update,
                validated_data.get('severity', instance.severity),
                is_resolved
            )

        return instance


class MaintenanceSerializer(serializers.ModelSerializer):
    services = serializers.PrimaryKeyRelatedField(
        many=True, queryset=Service.objects.all(), required=True)

    class Meta:
        model = Maintenance
        fields = ['id', 'title', 'description', 'services',
                  'scheduled_start', 'scheduled_end', 'organization']
        read_only_fields = ['organization']

    def validate(self, data):
        if data['scheduled_end'] <= data['scheduled_start']:
            raise serializers.ValidationError(
                {"scheduled_end": "End time must be after the start time."})

        if not data.get('services'):
            raise serializers.ValidationError(
                {"services": "At least one service must be selected."})

        return data

    def to_representation(self, instance):
        representation = super().to_representation(instance)
        representation['services'] = [
            {"id": service.id, "name": service.name}
            for service in instance.services.all()
        ]
        return representation
