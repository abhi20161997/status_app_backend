from django.contrib import admin
from .models import Organization, Team, Service, Incident, IncidentUpdate, Maintenance, Invitation


@admin.register(Organization)
class OrganizationAdmin(admin.ModelAdmin):
    list_display = ('name', 'slug', 'created_at')
    search_fields = ('name', 'slug')
    prepopulated_fields = {'slug': ('name',)}


@admin.register(Team)
class TeamAdmin(admin.ModelAdmin):
    list_display = ('name', 'slug', 'organization')
    list_filter = ('organization',)
    search_fields = ('name', 'slug', 'organization__name')
    prepopulated_fields = {'slug': ('name',)}


@admin.register(Service)
class ServiceAdmin(admin.ModelAdmin):
    list_display = ('name', 'slug', 'status', 'organization')
    list_filter = ('status', 'organization')
    search_fields = ('name', 'slug', 'description', 'organization__name')
    prepopulated_fields = {'slug': ('name',)}


@admin.register(Incident)
class IncidentAdmin(admin.ModelAdmin):
    list_display = ('title', 'severity', 'started_at',
                    'resolved_at', 'organization')
    list_filter = ('severity', 'organization', 'started_at', 'resolved_at')
    search_fields = ('title', 'description', 'organization__name')
    filter_horizontal = ('services',)


@admin.register(IncidentUpdate)
class IncidentUpdateAdmin(admin.ModelAdmin):
    list_display = ('incident', 'created_at')
    list_filter = ('incident', 'created_at')
    search_fields = ('incident__title', 'content')


@admin.register(Maintenance)
class MaintenanceAdmin(admin.ModelAdmin):
    list_display = ('title', 'scheduled_start',
                    'scheduled_end', 'organization')
    list_filter = ('organization', 'scheduled_start', 'scheduled_end')
    search_fields = ('title', 'description', 'organization__name')
    filter_horizontal = ('services',)


@admin.register(Invitation)
class InvitationAdmin(admin.ModelAdmin):
    list_display = ('email', 'inviter',
                    'created_at', 'organization')
    list_filter = ('organization', 'email')
    search_fields = ('email',)
