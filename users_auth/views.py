import os
import dotenv
import getpass
import subprocess
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import generics, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from .serializers import RegisterSerializer, LoginSerializer, AuthenticateScanIdSerializer

class RegisterView(generics.CreateAPIView):
    serializer_class = RegisterSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        token = RefreshToken.for_user(user)
        return Response({
            'refresh': str(token),
            'access': str(token.access_token),
        }, status=status.HTTP_201_CREATED)

class LoginView(APIView):
    serializer_class = LoginSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data
        token = serializer.get_token(user)
        return Response(token, status=status.HTTP_200_OK)
    
class AuthenticateScanId(APIView):

    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        serializer = AuthenticateScanIdSerializer(data=request.data)
        if serializer.is_valid():
            semgrep_id = serializer.validated_data['semgrep_id']
            snyk_id = serializer.validated_data['snyk_id']
            print(snyk_id)

            # Initialize the response status
            response_status = {
                'semgrep_authenticated': request.user.is_semgrep_authenticated,
                'snyk_authenticated': request.user.is_snyk_authenticated,
            }

            # Check Semgrep authentication
            # Before proceeding to this, we have to save the token in an environment variable
            os.environ["SEMGREP_APP_TOKEN"] = semgrep_id
            try:
                if not request.user.is_semgrep_authenticated or request.user.semgrep_id != semgrep_id:
                    semgrep_command = subprocess.run(['semgrep', 'login'], capture_output=True, text=True)
                    print(semgrep_command.stdout)
                    if semgrep_command.returncode == 0:
                        response_status['semgrep_authenticated'] = True
                        # Save semgrep_id to the user's profile if authenticated
                        request.user.semgrep_id = semgrep_id
                        request.user.is_semgrep_authenticated = True
                        request.user.save()
                    else:
                        raise Exception(f"Semgrep return code: {semgrep_command.returncode}")
                else:
                    response_status["semgrep_authenticated"] = f"Already Authenticated with given semgrep id \'{semgrep_id}\'"
            except Exception as err:
                print("Something went wrong - ", err.__str__())

            # Check Snyk authentication
            try:
                if not request.user.is_snyk_authenticated or request.user.snyk_id != snyk_id:
                    snyk_command = subprocess.run([f'/home/{getpass.getuser()}/Ghidorah/Ghidorah/binaries/snyk-linux', 'auth', snyk_id], capture_output=True, text=True)
                    print(snyk_command.returncode)
                    if snyk_command.returncode == 0:
                        print("here")
                        response_status['snyk_authenticated'] = True
                        # Save snyk_id to the user's profile if authenticated
                        request.user.snyk_id = snyk_id
                        request.user.is_snyk_authenticated = True
                        request.user.save()
                        print("here1")
                else:
                    response_status["snyk_authenticated"] = f"Already Authenticated with given snyk id \'{snyk_id}\'"
            except Exception as err:
                print(err)
                pass

            return Response(response_status, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
