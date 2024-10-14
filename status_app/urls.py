from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_nested import routers
from .views import (
    OrganizationViewSet, TeamViewSet, ServiceViewSet,
    IncidentViewSet, IncidentUpdateViewSet, MaintenanceViewSet,
    PublicStatusView, SignupView, LoginView, VerifyTokenView, IncidentsByServiceViewSet, InviteMemberView, AcceptInvitationView, ExternalStatusCheckAPI
)

# Main router
router = DefaultRouter()
router.register(r'organizations', OrganizationViewSet, basename='organization')

# Nested routers
org_router = routers.NestedDefaultRouter(
    router, r'organizations', lookup='organization')
org_router.register(r'teams', TeamViewSet, basename='organization-teams')
org_router.register(r'services', ServiceViewSet,
                    basename='organization-services')
org_router.register(r'incidents', IncidentViewSet,
                    basename='organization-incidents')
org_router.register(r'maintenances', MaintenanceViewSet,
                    basename='organization-maintenances')

# Incident updates are nested under incidents
incident_router = routers.NestedDefaultRouter(
    org_router, r'incidents', lookup='incident')
incident_router.register(
    r'updates', IncidentUpdateViewSet, basename='incident-updates')

# Incidents by service
service_router = routers.NestedDefaultRouter(
    org_router, r'services', lookup='service')
service_router.register(
    r'incidents', IncidentsByServiceViewSet, basename='service-incidents')


urlpatterns = [
    path('', include(router.urls)),
    path('', include(org_router.urls)),
    path('', include(incident_router.urls)),
    path('', include(service_router.urls)),
    path('organizations/<uuid:organization_id>/invite/',
         InviteMemberView.as_view(), name='invite-member'),
    path('invitations/<uuid:invitation_id>/accept/',
         AcceptInvitationView.as_view(), name='accept-invitation'),
    path('verify-token/', VerifyTokenView.as_view(), name='verify_token'),
    path('public-status/<uuid:org_id>/',
         PublicStatusView.as_view(), name='public-status'),
    path('signup/', SignupView.as_view(), name='signup'),
    path('login/', LoginView.as_view(), name='login'),
    path('external-status/<uuid:org_id>/',
         ExternalStatusCheckAPI.as_view(), name='external-status-check'),
]
