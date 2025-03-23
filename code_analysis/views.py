import os
import uuid
import json
import dotenv
from openai import OpenAI
import zipfile
import getpass
import tempfile
import subprocess
import openpyxl
from io import BytesIO
from pathlib import Path
from django.conf import settings
from django.http import FileResponse
from django.core.files.storage import FileSystemStorage
from rest_framework import status
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.response import Response
from rest_framework.views import APIView
from .models import GhidorahCodeAnalysisModel
from .serializers import CodeAnalysisSerializer, ScanResultsSerializer, SemgrepResultSerializer
from rest_framework.permissions import IsAuthenticated
from rest_framework import viewsets
from rest_framework.decorators import action
from django.utils.safestring import mark_safe

dotenv.load_dotenv('../.env')

class FileUploadView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]

    def post(self, request, *args, **kwargs):
        user = request.user
        file_obj = request.data.get('file')

        if not file_obj:
            return Response({"error": "No file provided"}, status=status.HTTP_400_BAD_REQUEST)
        
        # Check if the uploaded file is a zip file
        if not file_obj.name.endswith('.zip'):
            return Response({"error": "Only zip files are allowed"}, status=status.HTTP_400_BAD_REQUEST)

        # Save the file and directory path
        user_directory = f'{user.username}-secure_code_review'
        fs = FileSystemStorage(location=os.path.join(settings.MEDIA_ROOT, user_directory))
        filename = fs.save(file_obj.name, file_obj)
        file_path = os.path.join(user_directory, filename)

        code_analysis = GhidorahCodeAnalysisModel(user=user, uploaded_file=file_path, directory_path=user_directory)
        code_analysis.save()

        return Response(CodeAnalysisSerializer(code_analysis).data, status=status.HTTP_201_CREATED)

class CodeReviewView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        """get scan result of the given id"""
        scan_id = request.data.get("analysis_id")

        # dummy code
        try:
            uuid.uuid4(scan_id)
        except Exception as err: # try stuff
            return Response({"message": f"wrong {scan_id} provided"}, status.HTTP_400_BAD_REQUEST)

        code_details = GhidorahCodeAnalysisModel(user_id=request.user.id, id=scan_id)
        if code_details.exists():
            return code_details.first()

    def post(self, request, *args, **kwargs):
        user = request.user
        analysis_id = request.data.get('analysis_id')
        scan_type = request.data.get('scan_type')

        try:
            code_analysis = GhidorahCodeAnalysisModel.objects.get(id=analysis_id, user=user)
        except GhidorahCodeAnalysisModel.DoesNotExist:
            return Response({"error": "Code analysis record not found"}, status=status.HTTP_404_NOT_FOUND)

        # extract the zip file, at this point only the zip files will be accepted by the server
        # get the file_path
        file_path = os.path.join(settings.MEDIA_ROOT, str(code_analysis.uploaded_file))

        # get the output_dir
        output_dir = os.path.join(settings.MEDIA_ROOT, code_analysis.directory_path, 'output_dir')

        # extract the zip file located at file_path
        self.extract_zip_file(file_path, output_dir)
        
        #file_name = os.path.basename(file_path).split('.')[0]
        scan_directory_path = output_dir #os.path.join(output_dir, file_name)

        scan_results = {}
        scan_data = None
        response = {}

        # Run Scan based on scan_type
        try:
            if scan_type.lower().strip() == "semgrep":
                semgrep_command = ['semgrep', '--config', 'auto', '--json', scan_directory_path]
                semgrep_result = self.run_scan(semgrep_command, scan_directory_path, "semgrep")
                if semgrep_result[0]:
                    scan_data = semgrep_result[1]
            elif scan_type.lower().strip() == "snyk":
                snyk_command = [f'/home/{getpass.getuser()}/Ghidorah/Ghidorah/binaries/snyk-linux', '--json', 'code', 'test', scan_directory_path]
                snyk_result = self.run_scan(snyk_command, scan_directory_path, "snyk")
                if snyk_result[0]:
                    scan_data = snyk_result[1]
            else:
                return Response({f"Invalid option provided to \"scan_type\""}, status.HTTP_400_BAD_REQUEST)
        except Exception as err:
            print(err)
            return Response({f"Something Went Wrong\n Details: {err.__str__()}"}, status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        # Sort the results and save "results" data in the db
        print(scan_data)
        vulnerabilities, vulnerabilties_data = self.sort_results(scan_data, scan_type)
        print(vulnerabilties_data)
        
        response[scan_type] = vulnerabilities
        scan_results[scan_type] = vulnerabilties_data
        if scan_type.lower().strip() == "semgrep":
            code_analysis.semgrep_results = scan_results
            code_analysis.semgrep_check_ids = vulnerabilities
        elif scan_type.lower().strip() == "snyk":
            code_analysis.snyk_results = scan_results
            code_analysis.snyk_rule_ids = vulnerabilities
        code_analysis.save()

        # Once scan is completed; remove the contents from output_dir
        # coz now the scan data is saved in the database
        self.delete_directory_contents(output_dir)

        return Response(response, status=status.HTTP_200_OK)

    def run_scan(self, command, file_path, scan_type):
        temp_file = os.path.join(settings.MEDIA_ROOT, file_path, f"ghidorah_{scan_type}_result.json")
        print(temp_file)
        with open(temp_file, 'w') as t_fp:
            result = subprocess.run(command, stdout=t_fp, text=True)
        if result.returncode in [0, 1]:
            # get the json from temp file
            with open(temp_file, 'r') as fp:
                scan_result = json.load(fp)
                return (True, scan_result)
        else:
            return (False, [])
    
    def extract_zip_file(self, file_path, directory):
        if not zipfile.is_zipfile(file_path):
            print(f"{file_path} is not a valid zip file.")
            return
        
        # if directory exists, return True or else create 
        if not os.path.exists(directory):
            os.makedirs(directory, exist_ok=False)

        with zipfile.ZipFile(file_path, 'r') as zip_ref:
            zip_ref.extractall(directory)
        print(f"Extracted all files to {directory}")

    def sort_results(self, scan_results, scan_type):
        """
        Accept: scan results by snyk or semgrep
        Output: distinctive vulnerabilities name and their occurance
        """
        find_string = "check_id" if scan_type == "semgrep" else "ruleId"
        backup_data = scan_results
        final_result_set = set()
        try:
            if isinstance(scan_results, dict):
                if scan_type == "snyk":
                    scan_results = scan_results.get("runs")[0]
                if vulnerabilties_result:=scan_results.get('results', None):
                    for i in vulnerabilties_result:
                        check_id = i.get(find_string, None)
                        final_result_set.add(check_id)
            elif scan_results is None:
                return ([], {})
            
            # return the result_set to the caller
            return (list(final_result_set), backup_data)
        except Exception as err:
            print(err)
            return (False, ())

    def delete_directory_contents(self, directory):
        
        for filename in os.listdir(directory):
            file_path = os.path.join(directory, filename)
            
            try:
                if os.path.isfile(file_path) or os.path.islink(file_path):
                    # Delete the file or symbolic link
                    os.remove(file_path)
                elif os.path.isdir(file_path):
                    self.delete_directory_contents(file_path)
                    os.rmdir(file_path)
            except Exception as e:
                print(f"Failed to delete {file_path}. Reason: {e}")

class ScanResultsView(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    queryset = GhidorahCodeAnalysisModel.objects.all()
    serializer_class = ScanResultsSerializer

    def get_queryset(self):
        user = self.request.user
        return self.queryset.filter(user=user)

    @action(detail=False, methods=['get'])
    def get_user_scan_details(self, request):
        user = request.user

        try:
            scan_details = self.queryset.filter(user=user)
            serializer = self.get_serializer(scan_details, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def write_to_excel(self, data_dict, headers):
        """Write the data to temporary excel sheet"""

        excel_file_on_go = BytesIO()
        excel_workbook = openpyxl.Workbook()
        
        # Create the main sheet (0th sheet) for overview
        main_sheet = excel_workbook.active
        main_sheet.title = 'Vulnerabilities Overview'
        main_sheet.append(['Vulnerability Title', 'Sheet number'])

        # Create individual sheets for each check ID
        for index, (check_id, data) in enumerate(data_dict.items(), start=1):
            worksheet = excel_workbook.create_sheet(title=f'Vulnerability {index}')
            worksheet.append(headers)
            for row in data:
                worksheet.append(row)
            # Add link in the main sheet to this sheet
            main_sheet.append([f'{check_id}', f"Vulnerability {index}"])

        excel_workbook.save(excel_file_on_go)
        excel_file_on_go.seek(0)  # Reset file pointer to start

        return excel_file_on_go

    @action(detail=False, methods=["post"])
    def generate_excel_report(self, request):
        """
        Generate excel workbook that contains N number of work sheets
        """

        scan_type = request.data.get("scan_type")
        analysis_id = request.data.get("analysis_id")

        if not scan_type or not analysis_id:
            return Response({"error": "Both 'scan_type' and 'analysis_id' must be provided"}, status=status.HTTP_400_BAD_REQUEST)

        if scan_type == "semgrep":
            response_data = self.get_semgrep_affected_paths(request, analysis_id)
        elif scan_type == "snyk":
            response_data = self.get_snyk_affected_paths(request, analysis_id)
        else:
            return Response({"error": f"Unsupported scan type: {scan_type}"}, status=status.HTTP_400_BAD_REQUEST)

        if isinstance(response_data, Response):
            return response_data
        elif isinstance(response_data, BytesIO):    
            file_response = FileResponse(response_data, as_attachment=True, filename=f"{scan_type}_output.xlsx")
            return file_response
        return Response({"message": "Something went wrong!!"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def get_semgrep_affected_paths(self, request, analysis_id):
        try:
            ghidorah_entry = GhidorahCodeAnalysisModel.objects.get(user=request.user, id=analysis_id)
        except GhidorahCodeAnalysisModel.DoesNotExist:
            return Response({"error": "Analysis entry not found"}, status=status.HTTP_404_NOT_FOUND)

        data_dict = {}
        check_ids = ghidorah_entry.semgrep_check_ids
        if check_ids is not None:
            semgrep_results = ghidorah_entry.semgrep_results.get("semgrep")
        else:
            return Response({"message": f"No history of code review scans with given analysis id: \'{analysis_id}\'"})

        for check_id in check_ids:
            my_data = []
            for result in semgrep_results.get("results", []):
                if result.get("check_id", "").startswith(check_id):
                    my_data.append([
                        result.get('extra', {}).get('metadata', {}).get('impact'),
                        ', '.join([i.split(':')[0] for i in result.get('extra', {}).get('metadata', {}).get('cwe', [""])]),
                        result.get('path', ''),
                        result.get('start', {}).get('line', ''),
                        result.get('start', {}).get('col', ''),
                        result.get('extra', {}).get('message', ''),
                        result.get('extra', {}).get('lines', ''),
                    ])
            data_dict[check_id] = my_data

        excel_file = self.write_to_excel(data_dict, headers=['Severity', 'CWE', 'File Path', 'Line', 'Column', 'Description', 'Code'])
        return excel_file
    
    def get_snyk_affected_paths(self, request, analysis_id):
        try:
            ghidorah_entry = GhidorahCodeAnalysisModel.objects.get(user=request.user, id=analysis_id)
        except GhidorahCodeAnalysisModel.DoesNotExist:
            return Response({"error": "Analysis entry not found"}, status=status.HTTP_404_NOT_FOUND)

        data_dict = {}
        rule_ids = ghidorah_entry.snyk_rule_ids
        if rule_ids is not None:
            snyk_results = ghidorah_entry.snyk_results.get("snyk").get("runs")[0]
        else:
            return Response({"message": f"No history of code review scans with given analysis id: \'{analysis_id}\'"})

        for rule_id in rule_ids:
            my_data = []
            snyk_rules = snyk_results.get("tool", {}).get("driver", {}).get("rules", [])
            for result in snyk_results.get("results", []):
                if result.get("ruleId", "").startswith(rule_id):
                    my_data.append([])
                    # append more data to the last appended item in my_data list
                    for each_rule in snyk_rules:
                        if each_rule.get("id", "") == rule_id:
                            my_data[-1].append(each_rule.get('defaultConfiguration', {}).get('level'))
                            my_data[-1].append(', '.join(i for i in each_rule.get("properties", {}).get('cwe', [])))
                            break
                    # append more data
                    my_data[-1].extend([
                        result.get('locations', [{}])[0].get("physicalLocation", {}).get("artifactLocation", {}).get("uri"),
                        result.get('locations', [{}])[0].get('physicalLocation', {}).get('region', {}).get('startLine'),
                        result.get('locations', [{}])[0].get('physicalLocation', {}).get('region', {}).get('startColumn'),
                        result.get('message', {}).get('text'),
                        str(', '.join(i for i in result.get("message", {}).get("arguments")))
                    ])

            data_dict[rule_id] = my_data

        excel_file = self.write_to_excel(data_dict, headers=['Severity', 'CWE', 'File Path', 'Line', 'Column', 'Description', 'Code'])
        return excel_file
    
    @action(detail=False, methods=['post'], url_path='generate_snyk_html')
    def generate_snyk_html(self, request):
        try:
            user = request.user
            analysis_id = request.data.get("analysis_id")

            ghidorah_entry = GhidorahCodeAnalysisModel.objects.get(user=user, id=analysis_id)
            snyk_results = ghidorah_entry.snyk_results
            if not snyk_results:
                return Response({"error": f"No history of scanning found with the given id: {analysis_id}"})
            snyk_results = snyk_results.get("snyk")

            # create a temporary directory
            with tempfile.TemporaryDirectory() as temp_directory:
                # Extract the zip file required for this
                CodeReviewView().extract_zip_file(ghidorah_entry.uploaded_file.path, temp_directory)

                # create a temporary file
                with open(f'{temp_directory}/input.json', 'w') as file:
                    json.dump(snyk_results, file)

                # run snyk-to-html command
                snyk_json_output = subprocess.run(["snyk-to-html", "-i", f"{temp_directory}/input.json", "-o", f"{temp_directory}/output.html"], stdout=open(f"{temp_directory}/stdout.txt", 'w'), cwd=temp_directory, text=True, stderr=subprocess.DEVNULL)

                if snyk_json_output.returncode != 0:
                    return Response({"error": f"Error running snyk-to-html"})

                # put the file contents into a buffer
                with open(f"{temp_directory}/output.html", 'r') as file:
                    temporary_output_file = BytesIO(file.read().encode())

                temporary_output_file.seek(0)

                response = FileResponse(temporary_output_file, as_attachment=True, filename='snyk_report.html')
                return response
        
        except Exception as e:
            return Response(f"Error: {str(e)}", status=500)
        
class VulnerabilityDescriptionView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        # Parse the incoming Semgrep JSON result
        serializer = SemgrepResultSerializer(data=request.data)
        if serializer.is_valid():
            semgrep_result = serializer.validated_data
            
            # Construct the prompt for GPT-4
            prompt = f"""
            The following is a Semgrep result in JSON format, which describes a vulnerability in code:

            {semgrep_result}

            Based on this, provide a detailed description of the vulnerability identified, explain why it's a security issue, and suggest the best ways to mitigate it. 
            Also, explain the potential risks if the vulnerability is not fixed.
            """

            try:
                openai_obj = OpenAI(
                    api_key=os.getenv("OPENAI_API_KEY")
                )
                response = openai_obj.chat.completions.create(
                    model="gpt-4o",
                    messages=[
                        {"role": "developer"},
                        {
                            "role": "user",
                            "content": prompt,
                        },
                    ]
                )
                return Response(
                    {"message": response.choices[0].text.strip()},
                    status=status.HTTP_200_OK
                )
            except Exception as err:
                return Response(
                    {"error": f"An error occurred with OpenAI API: {str(err.__str__())}"},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
        else:
            return Response(
                {"error": "Invalid Semgrep JSON format\nProvide a different format in the request"},
                status=status.HTTP_400_BAD_REQUEST
            )