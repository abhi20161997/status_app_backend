# status_app/views.py

from django.contrib.auth.models import User
from rest_framework_simplejwt.tokens import UntypedToken
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework import permissions, status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import viewsets, filters, status, serializers, permissions
from rest_framework.permissions import IsAuthenticated
from rest_framework.pagination import PageNumberPagination
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework_simplejwt.tokens import RefreshToken, UntypedToken
from rest_framework.decorators import action
from rest_framework.exceptions import PermissionDenied
from rest_framework_simplejwt.exceptions import TokenError, TokenBackendError
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
from .utils import send_ws_message
from django.core.mail import send_mail
from django.conf import settings
from django.urls import reverse
from django.db import transaction
from django.shortcuts import get_object_or_404
from django.db import IntegrityError
from .models import Team, Organization
from .serializers import TeamSerializer
from django.utils import timezone

from .models import Organization, Team, Service, Incident, IncidentUpdate, Maintenance, User, OrganizationMembership, Invitation
from .serializers import OrganizationSerializer, TeamSerializer, ServiceSerializer, IncidentSerializer, IncidentUpdateSerializer, MaintenanceSerializer, UserSerializer, OrganizationDetailSerializer, ServiceCreateSerializer


# Pagination
class StandardResultsSetPagination(PageNumberPagination):
    page_size = 10
    page_size_query_param = 'page_size'
    max_page_size = 100


# Mixins
class OrganizationQuerySetMixin:
    def get_queryset(self):
        user_orgs = self.request.user.teams.values_list(
            'organization', flat=True)
        return super().get_queryset().filter(organization__in=user_orgs)


# Custom Permissions
class IsOrganizationMember(permissions.BasePermission):
    def has_permission(self, request, view):
        organization_id = view.kwargs.get('organization_pk')
        return request.user.organizations.filter(id=organization_id).exists()


# Authentication Views
class SignupView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        email = request.data.get('email')

        if not username or not password or not email:
            return Response({'error': 'Please provide username, password, and email'}, status=status.HTTP_400_BAD_REQUEST)

        if User.objects.filter(username=username).exists():
            return Response({'error': 'Username already exists'}, status=status.HTTP_400_BAD_REQUEST)

        user = User.objects.create_user(
            username=username, password=password, email=email)
        refresh = RefreshToken.for_user(user)

        user_data = {
            "id": user.id,
            "username": user.username,
            "email": user.email,
        }

        return Response({
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            'user_data': user_data
        }, status=status.HTTP_201_CREATED)


class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')

        user = User.objects.filter(username=username).first()

        if user is None or not user.check_password(password):
            return Response({'error': 'Invalid credentials'}, status=status.HTTP_400_BAD_REQUEST)

        refresh = RefreshToken.for_user(user)
        user_data = {
            "id": user.id,
            "username": user.username,
            "email": user.email,
        }

        return Response({
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            'user_data': user_data
        })


class VerifyTokenView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        token = request.data.get("token")
        if not token:
            return Response({"detail": "Token is required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Decode the token to get the user info
            validated_token = UntypedToken(token)
            user_id = validated_token['user_id']
            user = User.objects.get(id=user_id)

            user_data = {
                "id": user.id,
                "username": user.username,
                "email": user.email,
                # Add any other fields you want to include
            }

            return Response({"valid": True, "user_data": user_data}, status=status.HTTP_200_OK)
        except (TokenError, TokenBackendError, User.DoesNotExist):
            return Response({"valid": False}, status=status.HTTP_401_UNAUTHORIZED)


class UserDetailView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        user = request.user
        user_data = {
            "id": user.id,
            "username": user.username,
            "email": user.email,
        }
        return Response(user_data, status=status.HTTP_200_OK)


# Organization Management Views
class OrganizationViewSet(viewsets.ModelViewSet):
    queryset = Organization.objects.all()
    serializer_class = OrganizationDetailSerializer
    permission_classes = [IsAuthenticated]
    pagination_class = StandardResultsSetPagination
    filter_backends = [DjangoFilterBackend,
                       filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['name']
    search_fields = ['name']
    ordering_fields = ['name', 'created_at']

    def get_queryset(self):
        return Organization.objects.filter(members=self.request.user).distinct()

    @transaction.atomic
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Save the organization with the current user as owner
        organization = serializer.save(owner=request.user)

        # Create the OrganizationMembership for the owner
        OrganizationMembership.objects.create(
            user=request.user,
            organization=organization,
            role='owner'
        )

        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)

    def perform_create(self, serializer):
        pass


class InviteMemberView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    @transaction.atomic
    def post(self, request, organization_id):
        organization = Organization.objects.get(id=organization_id)
        if not organization.members.filter(id=request.user.id).exists():
            return Response({"error": "You are not a member of this organization"}, status=status.HTTP_403_FORBIDDEN)

        email = request.data.get('email')
        invitation = Invitation.objects.create(
            email=email,
            organization=organization,
            inviter=request.user
        )
        # sending invite over email
        send_invitation_email(invitation=invitation)
        return Response({"message": "Invitation sent"}, status=status.HTTP_201_CREATED)


class AcceptInvitationView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    @transaction.atomic
    def post(self, request, invitation_id):
        invitation = Invitation.objects.get(id=invitation_id)
        if invitation.email != request.user.email:
            return Response({"error": "This invitation is not for you"}, status=status.HTTP_403_FORBIDDEN)

        if invitation.accepted:
            return Response({"error": "This invitation has already been accepted"}, status=status.HTTP_400_BAD_REQUEST)

        OrganizationMembership.objects.create(
            user=request.user,
            organization=invitation.organization,
            role='member'
        )
        invitation.accepted = True
        invitation.save()
        return Response({"message": "You have joined the organization"}, status=status.HTTP_200_OK)


# Team Management Views
class TeamViewSet(viewsets.ModelViewSet):
    serializer_class = TeamSerializer
    permission_classes = [IsAuthenticated, IsOrganizationMember]
    pagination_class = StandardResultsSetPagination
    filter_backends = [DjangoFilterBackend,
                       filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['name']
    search_fields = ['name']
    ordering_fields = ['name']

    def get_queryset(self):
        return Team.objects.filter(organization_id=self.kwargs['organization_pk'])

    @transaction.atomic
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            team = self.perform_create(serializer)
            headers = self.get_success_headers(serializer.data)
            return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)
        except IntegrityError:
            return Response({"error": "A team with this slug already exists in this organization."},
                            status=status.HTTP_400_BAD_REQUEST)

    def perform_create(self, serializer):
        organization_id = self.kwargs['organization_pk']
        organization = Organization.objects.get(id=organization_id)
        team = serializer.save(organization=organization)
        team.members.add(self.request.user)
        return team

    @action(detail=True, methods=['get'])
    def members(self, request, organization_pk=None, pk=None):
        team = self.get_object()
        members = team.members.all()
        serializer = UserSerializer(members, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=['post'])
    @transaction.atomic
    def add_members(self, request, organization_pk=None, pk=None):
        team = self.get_object()
        member_ids = request.data.get('member_ids', [])
        organization = team.organization
        new_members = User.objects.filter(
            id__in=member_ids, organizations=organization)
        team.members.add(*new_members)
        return Response({'status': 'members added', 'count': new_members.count()})

    @action(detail=True, methods=['post'])
    @transaction.atomic
    def add_member(self, request, organization_pk=None, pk=None):
        team = self.get_object()
        email = request.data.get('email')

        if not email:
            return Response({'error': 'Email is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(
                email=email, organizations=team.organization)
        except User.DoesNotExist:
            return Response({'error': 'User not found or not a member of this organization'},
                            status=status.HTTP_404_NOT_FOUND)

        if user in team.members.all():
            return Response({'error': 'User is already a member of this team'},
                            status=status.HTTP_400_BAD_REQUEST)

        team.members.add(user)
        return Response({'status': 'User added to team'}, status=status.HTTP_200_OK)

    @action(detail=True, methods=['post'])
    @transaction.atomic
    def remove_member(self, request, organization_pk=None, pk=None):
        team = self.get_object()
        user_id = request.data.get('user_id')

        if not user_id:
            return Response({'error': 'User ID is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(
                id=user_id, organizations=team.organization)
        except User.DoesNotExist:
            return Response({'error': 'User not found or not a member of this organization'},
                            status=status.HTTP_404_NOT_FOUND)

        if user not in team.members.all():
            return Response({'error': 'User is not a member of this team'},
                            status=status.HTTP_400_BAD_REQUEST)

        team.members.remove(user)
        return Response({'status': 'User removed from team'}, status=status.HTTP_200_OK)

    @action(detail=True, methods=['get'])
    def services(self, request, organization_pk=None, pk=None):
        team = self.get_object()
        services = team.services.all()
        serializer = ServiceSerializer(services, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=['post'])
    @transaction.atomic
    def add_service(self, request, organization_pk=None, pk=None):
        team = self.get_object()
        serializer = ServiceCreateSerializer(data=request.data)

        if serializer.is_valid():
            service = serializer.save(
                team=team, organization=team.organization)
            return Response(ServiceSerializer(service).data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=True, methods=['delete'])
    @transaction.atomic
    def remove_service(self, request, organization_pk=None, pk=None):
        team = self.get_object()
        service_id = request.query_params.get('service_id')
        if not service_id:
            return Response({"error": "service_id is required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            service = team.services.get(pk=service_id)
        except Service.DoesNotExist:
            return Response({"error": "Service not found"}, status=status.HTTP_404_NOT_FOUND)

        service.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


# Service Management Views
class ServiceViewSet(viewsets.ModelViewSet):
    serializer_class = ServiceSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend,
                       filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['name', 'status', 'organization', 'team']
    search_fields = ['name', 'description']
    ordering_fields = ['name', 'status']

    def get_queryset(self):
        return Service.objects.filter(organization_id=self.kwargs['organization_pk'])

    def perform_create(self, serializer):
        organization_id = self.kwargs['organization_pk']
        organization = Organization.objects.get(id=organization_id)
        serializer.save(organization=organization)

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(
            instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)

        if getattr(instance, '_prefetched_objects_cache', None):
            instance._prefetched_objects_cache = {}

        return Response(serializer.data)

    def perform_update(self, serializer):
        instance = serializer.save()
        send_ws_message(
            instance.organization.id,
            "service_update",
            ServiceSerializer(instance).data
        )

    @action(detail=True, methods=['post'])
    def assign_team(self, request, organization_pk=None, pk=None):
        service = self.get_object()
        team_id = request.data.get('team_id')
        try:
            team = Team.objects.get(
                id=team_id, organization_id=organization_pk)
            service.team = team
            service.save()
            return Response({'status': 'service assigned to team'})
        except Team.DoesNotExist:
            return Response({'error': 'Team not found'}, status=status.HTTP_404_NOT_FOUND)


# Incident Management Views
class IncidentViewSet(viewsets.ModelViewSet):
    serializer_class = IncidentSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        organization_pk = self.kwargs.get('organization_pk')
        user = self.request.user

        # if not user.teams.filter(organization__id=organization_pk).exists():
        #     raise PermissionDenied(
        #         "You do not have permission to access this organization.")

        return Incident.objects.filter(organization_id=organization_pk)

    def perform_create(self, serializer):
        instance = serializer.save(
            organization_id=self.kwargs.get('organization_pk'))
        send_ws_message(
            instance.organization.id,
            "incident_update",
            IncidentSerializer(instance).data
        )

    def perform_update(self, serializer):
        instance = serializer.save()
        send_ws_message(
            instance.organization.id,
            "incident_update",
            IncidentSerializer(instance).data
        )

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(
            instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)

        if getattr(instance, '_prefetched_objects_cache', None):
            instance._prefetched_objects_cache = {}

        return Response(serializer.data)

    @action(detail=True, methods=['get', 'post'])
    def updates(self, request, organization_pk=None, pk=None):
        incident = self.get_object()

        if request.method == 'GET':
            updates = incident.updates.all().order_by('-created_at')
            serializer = IncidentUpdateSerializer(updates, many=True)
            return Response(serializer.data)

        elif request.method == 'POST':
            serializer = IncidentUpdateSerializer(
                data=request.data, context={'incident': incident})
            if serializer.is_valid():
                update = serializer.save()
                send_ws_message(
                    incident.organization.id,
                    "incident_update",
                    IncidentSerializer(incident).data
                )
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class IncidentUpdateViewSet(viewsets.ModelViewSet):
    serializer_class = IncidentUpdateSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        organization_pk = self.kwargs.get('organization_pk')
        incident_pk = self.kwargs.get('incident_pk')
        user = self.request.user

        # Check if the user has access to the organization
        if not user.teams.filter(organization__id=organization_pk).exists():
            raise PermissionDenied(
                "You do not have permission to access this organization.")

        # Check if the incident belongs to the organization
        incident = Incident.objects.filter(
            id=incident_pk, organization_id=organization_pk).first()
        if not incident:
            raise PermissionDenied(
                "This incident does not belong to the specified organization.")

        return IncidentUpdate.objects.filter(incident=incident)

    def perform_create(self, serializer):
        incident_pk = self.kwargs.get('incident_pk')
        incident = Incident.objects.get(pk=incident_pk)
        serializer.save(incident=incident)


class IncidentsByServiceViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = IncidentSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        organization_pk = self.kwargs.get('organization_pk')
        service_pk = self.kwargs.get('service_pk')
        user = self.request.user

        # if not user.teams.filter(organization__id=organization_pk).exists():
        #     raise PermissionDenied(
        #         "You do not have permission to access this organization.")

        return Incident.objects.filter(
            organization_id=organization_pk,
            services__id=service_pk
        ).distinct()


# Maintenance Management Views
class MaintenanceViewSet(viewsets.ModelViewSet):
    serializer_class = MaintenanceSerializer
    permission_classes = [IsAuthenticated]
    pagination_class = StandardResultsSetPagination
    filter_backends = [DjangoFilterBackend,
                       filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['scheduled_start', 'scheduled_end']
    search_fields = ['title', 'description']
    ordering_fields = ['scheduled_start', 'scheduled_end']

    def get_queryset(self):
        return Maintenance.objects.filter(organization_id=self.kwargs['organization_pk'])

    def create(self, request, *args, **kwargs):
        organization_id = self.kwargs['organization_pk']

        # Ensure 'services' is in the request data
        if 'services' not in request.data:
            return Response({"services": ["This field is required."]}, status=status.HTTP_400_BAD_REQUEST)

        # Validate that the services belong to the organization
        service_ids = request.data.get('services', [])
        valid_services = Service.objects.filter(
            organization_id=organization_id, id__in=service_ids)
        if len(valid_services) != len(service_ids):
            return Response({"services": ["One or more services do not belong to this organization."]}, status=status.HTTP_400_BAD_REQUEST)

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)

    def perform_create(self, serializer):
        instance = serializer.save(
            organization_id=self.kwargs.get('organization_pk'))
        send_ws_message(
            instance.organization.id,
            "maintenance_update",
            MaintenanceSerializer(instance).data
        )

    def perform_update(self, serializer):
        instance = serializer.save()
        send_ws_message(
            instance.organization.id,
            "maintenance_update",
            MaintenanceSerializer(instance).data
        )

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()

        # Validate services if they're being updated
        if 'services' in request.data:
            service_ids = request.data.get('services', [])
            valid_services = Service.objects.filter(
                organization_id=instance.organization_id, id__in=service_ids)
            if len(valid_services) != len(service_ids):
                return Response({"services": ["One or more services do not belong to this organization."]}, status=status.HTTP_400_BAD_REQUEST)

        serializer = self.get_serializer(
            instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)

        return Response(serializer.data)


# Public Status Views
class PublicStatusView(APIView):
    permission_classes = [AllowAny]

    def get(self, request, org_id):
        organization = get_object_or_404(Organization, id=org_id)
        services = Service.objects.filter(organization=organization)
        incidents = Incident.objects.filter(
            organization=organization,
            resolved_at__isnull=True
        ).prefetch_related('updates')
        maintenances = Maintenance.objects.filter(
            organization=organization,
            scheduled_end__gt=timezone.now()
        )

        incident_data = []
        for incident in incidents:
            incident_serializer = IncidentSerializer(incident).data
            updates = incident.updates.order_by(
                '-created_at')[:5]  # Get the 5 most recent updates
            incident_serializer['recent_updates'] = IncidentUpdateSerializer(
                updates, many=True).data
            incident_data.append(incident_serializer)

        return Response({
            'organization': OrganizationSerializer(organization).data,
            'services': ServiceSerializer(services, many=True).data,
            'active_incidents': incident_data,
            'upcoming_maintenances': MaintenanceSerializer(maintenances, many=True).data,
            'ws_url': f"{settings.WS_BASE_URL}/ws/status/{org_id}/"
        })


class ExternalStatusCheckAPI(APIView):
    permission_classes = [AllowAny]

    def get(self, request, org_id):
        try:
            organization = Organization.objects.get(id=org_id)
            services = Service.objects.filter(organization=organization)
            active_incidents = Incident.objects.filter(
                organization=organization,
                resolved_at__isnull=True
            )

            # Calculate overall status
            if active_incidents.filter(severity__in=['high', 'critical']).exists():
                overall_status = 'critical'
            elif active_incidents.filter(severity='medium').exists() or services.filter(status__in=['degraded', 'partial']).exists():
                overall_status = 'degraded'
            elif active_incidents.filter(severity='low').exists():
                overall_status = 'minor'
            else:
                overall_status = 'operational'

            response_data = {
                'overall_status': overall_status,
                'services': ServiceSerializer(services, many=True).data,
                'active_incidents_count': active_incidents.count(),
            }

            return Response(response_data)
        except Organization.DoesNotExist:
            return Response({"error": "Organization not found"}, status=status.HTTP_404_NOT_FOUND)


# Utility Functions
def send_invitation_email(invitation):
    # Email subject
    subject = f"Invitation to join {invitation.organization.name}"

    # URL for accepting the invitation (constructs the absolute URL)
    full_accept_url = f"{
        settings.FRONTEND_BASE_URL}/invitations/{invitation.id}/accept"

    # Email message body
    message = f"""
    You've been invited to join {invitation.organization.name} on our platform.

    Click the following link to accept the invitation:
    {full_accept_url}

    If you didn't expect this invitation, you can safely ignore this email.
    """

    # Send the email
    send_mail(
        subject,  # Subject
        message,  # Message body
        settings.DEFAULT_FROM_EMAIL,  # Sender email
        [invitation.email],  # Recipient email (list of recipients)
        fail_silently=False,  # Raise an error if sending fails
    )
