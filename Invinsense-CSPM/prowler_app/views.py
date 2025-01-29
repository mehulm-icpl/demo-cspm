import json, os, re, subprocess, threading, warnings
import boto3
from datetime import datetime
from django.contrib import messages
from django.contrib.auth import login, authenticate
from django.contrib.auth.decorators import login_required
from django.contrib.auth.password_validation import MinimumLengthValidator, CommonPasswordValidator, NumericPasswordValidator
from django.shortcuts import render, redirect
from django.contrib import messages
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.contrib.auth.models import User
from django.http import HttpResponse
from django.template.loader import render_to_string
from invinsense_cspm.settings import BASE_DIR
from prowler_app.models import Awsmodal
from prowler_app.pdffiles.marg import call
from prowler_app.utils import *

AWS_ACCOUNT_COUNT = 0

# Create your views here.

# ---------------------------- get profile name's first latter ------------------------------------------------
def get_profile_first_img(request):
    if request.user.is_authenticated:
        name = str(request.user)
        if name:
            # Get the first letter and capitalize it
            first_letter = name[0].capitalize()
    # Ignore the warning in this specific code block
    warnings.filterwarnings("ignore", message="When grouping with a length-1 list-like, you will need to pass a length-1 tuple to get_group in a future version of pandas.")
    return first_letter
    
# ------------------------------- DASHBOARD ------------------------------------------

@login_required
def dashboard(request):
    first_letter = get_profile_first_img(request)
      
    number_of_profiles = count_aws_profiles()
    folder_path = os.path.join(BASE_DIR, 'output')
    all_files = os.listdir(folder_path)
    json_files = [file for file in all_files if file.endswith('.json') and not file.endswith('.ocsf.json')]
    keys_to_extract = ['ServiceName', 'Status', 'Severity', 'ResourceType', 'ResourceDetails', 'Region', 'CheckTitle',
                            'RelatedUrl']
    next_status_keys = {}
    
    # get those files which belong to your account number
    files_with_account_id = []
    unique_files = set()

    for file_name in json_files:
        # Use regular expression to match the account ID
        match = re.search(r'-(\d+)-', file_name)
        if match:
            file_with_ac = match.group(1)
            aws_account_id_lst = []
            user_aws_accounts = Awsmodal.objects.filter(user=request.user)
            aws_account_ids = [aws_account.aws_account_id for aws_account in user_aws_accounts]

            # Check if the file's account ID matches any of the user's account IDs
            if file_with_ac in aws_account_ids:
                # Create a unique identifier for the file
                unique_id = (file_name, file_with_ac)
                if unique_id not in unique_files:
                    files_with_account_id.append(file_name)
                    unique_files.add(unique_id)

    cnt = len(files_with_account_id)
    # cnt = 0
    if number_of_profiles == 0:
        #kindly integrate your profile
        context = {
            'not_integrated':'not_integrated',
            'number_of_profiles':number_of_profiles,
            'number_of_scanned_files':'0',
            'html_meter' : '0',
            "first_letter":first_letter+".png",
        }
    
    elif cnt == 0:
        #perfome your first scan
        context = {
            'empty_history':'empty_history',
            'number_of_profiles':number_of_profiles,
            'number_of_scanned_files':'0',
            'html_meter' : '0',
            "first_letter":first_letter+".png",
        }
    
    else:
        output_folder_path = os.path.join(BASE_DIR, "output")
        json_files_from_output = []

        for filename in os.listdir(output_folder_path):
            if filename.endswith(".json") and "prowler" in filename and not filename.endswith(".ocsf.json"):
                json_files_from_output.append(filename)

        # Sort the list of file names by modification time (most recent first)
        sorted_files = sorted(json_files_from_output, key=lambda x: os.path.getatime(os.path.join(output_folder_path, x)), reverse=True)

        second_latest_file = sorted_files[1] if len(sorted_files) > 1 else None
        request.session['second_latest_file'] = second_latest_file

        scaned_file = request.session.get('file_from_history')
        print("Scanned file: ",scaned_file)
        print("next file: ",request.session.get('next_file_from_selected_file'))
        next_file = request.session.get('next_file_from_selected_file')
        if next_file is not None:
            file_path = os.path.join(BASE_DIR, "output", next_file)
            print(next_file)
            refactor_json(file_path)
            with open(file_path) as f:
                next_file_date = json.load(f)
                
            next_file_data_obj = get_all_data(next_file)
            next_status_key = 'Status'
            next_status_keys = get_json_data(next_status_key, next_file_date)
        else:
            next_file = request.session.get("second_latest_file")
            file_path = os.path.join(BASE_DIR, "output", next_file)
            print(next_file)
            refactor_json(file_path)
            with open(file_path) as f:
                next_file_date = json.load(f)
                
            next_file_data_obj = get_all_data(next_file)
            next_status_key = 'Status'
            next_status_keys = get_json_data(next_status_key, next_file_date)
            
        if scaned_file == None:
            newest_file = max(files_with_account_id, key=lambda filename: int(filename.split('-')[-1].split('.')[0]))
        else:
            newest_file = scaned_file

        display_file_name = newest_file
        file_path = os.path.join(BASE_DIR, "output", newest_file)
        print(file_path)
        refactor_json(file_path)
        with open(file_path) as f:
            data = json.load(f)
        
        data_obj = [{key: item[key] for key in keys_to_extract} for item in data]
        filtered_data_list = data_obj
        
        region_to_extract = ['Region','Status']
        filtered_region_list = [{key: item[key] for key in region_to_extract} for item in data]
        
        
        count_dict = {}

        # Iterate over the data and count occurrences
        for entry in filtered_region_list:
            region = entry['Region']
            
            # Update the count in the dictionary
            count_dict[region] = count_dict.get(region, 0) + 1

        # Print the resulting dictionary
        # print(count_dict)
        
        region_latlog = {'us-east-1':'38.83, -77.04', 'us-east-2':'39.05, -84.51', 'us-west-1':'37.77, -122.42',
                        'us-west-2':'45.52, -122.68', 'ca-central-1':'45.42, -75.70', 'eu-west-1':'53.35, -6.26',
                        'eu-west-2':'51.51, -0.12', 'eu-central-1':'50.11, 8.68', 'ap-south-1':'19.08, 72.88',
                        'ap-southeast-1':'1.35, 103.82'}

        # set the file name in session ----

        request.session['current_json_file'] = display_file_name


        # savirity ----------------------

        severity_key = 'Severity'
        severity_keys = get_json_data(severity_key, data)
        values_list_ser = list(severity_keys.values())
        high_cnt = 0
        critical_cnt = 0
        low_cnt = 0
        medium_cnt = 0
        try:
            low_cnt = values_list_ser[0]
            medium_cnt = values_list_ser[1]
            high_cnt = values_list_ser[2]
            critical_cnt = values_list_ser[3]
        except IndexError as e:
            print(f"Index out of bounds error: {e}")

        # for donut chart ------------------------
        result_list = doghnut_chart(data_obj)
        print("This is result list: ",result_list)

        # pie chart -------------------

        status_key = 'Status'
        status_counts = get_json_data(status_key, data)
        labels, values = pie_chart(status_counts)

        # service bar chart --------------

        chart_div_service = stack_bar_service(data)

        # regian bar chart ---------------

        chart_div = stack_bar_region(data)
        
        # top 10 most common issue ------------------------------
        
        most_common_problem_var = enumerate(most_common_problem(data), start=1)
        common_issue_count = enumerate(most_common_problem_var, start=1)

        # score meter calcultion ---------

        status_key = 'Status'
        status_keys = get_json_data(status_key, data)
        total = 0
        
        region_key = 'Region'
        region_keys = get_json_data(region_key, data)
        
        #------------ diff calculation ---------------------------
       
        pass_cnt = status_keys.get('PASS', 0)
        fail_cnt = status_keys.get('FAIL', 0)
        info_cnt = status_keys.get('INFO', 0)
        for i in status_keys.values():
            total = total + i
        next_pass_cnt = next_status_keys.get('PASS', 0)
        next_fail_cnt = next_status_keys.get('FAIL', 0)
        next_info_cnt = next_status_keys.get('INFO', 0)
        next_total = next_pass_cnt + next_fail_cnt + next_info_cnt
        
        
        next_pass_cnt = diff_between_scan(pass_cnt,next_pass_cnt)
        next_fail_cnt = diff_between_scan(fail_cnt,next_fail_cnt)
        next_info_cnt = diff_between_scan(info_cnt,next_info_cnt)
        next_total = diff_between_scan(total,next_total)
        
        metre = round((pass_cnt / total) * 100)
        metre = round((pass_cnt / total) * 100)
        #meter_css = 472 - (472 * (metre / 100))
        if metre >50:
            css2 = metre - 50
            css1 = metre - css2
        else:
            css1 = metre
            css2 = 0
        
        # vector map -------------------------------------------
        vector_map_dict = {
        'us-east-1': {'region': 'us-east-1', 'coordinate': ['38.83', '-77.04'], 'Status': 'FAIL'},
        'us-east-2': {'region': 'us-east-2', 'coordinate': ['39.05', '-84.51'], 'Status': 'FAIL'},
        'us-west-1': {'region': 'us-west-1', 'coordinate': ['37.77', '-122.42'], 'Status': 'FAIL'},
        'us-west-2': {'region': 'us-west-2', 'coordinate': ['45.52', '-122.68'], 'Status': 'FAIL'},
        'ca-central-1': {'region': 'ca-central-1', 'coordinate': ['45.42', '-75.70'], 'Status': 'PASS'},
        'eu-west-1': {'region': 'eu-west-1', 'coordinate': ['53.35', '-6.26'], 'Status': 'PASS'},
        'eu-west-2': {'region': 'eu-west-2', 'coordinate': ['51.51', '-0.12'], 'Status': 'PASS'},
        'eu-central-1': {'region': 'eu-central-1', 'coordinate': ['50.11', '8.68'], 'Status': 'PASS'},
        'ap-south-1': {'region': 'ap-south-1', 'coordinate': ['19.08', '72.88'], 'Status': 'PASS'},
        'ap-southeast-1': {'region': 'ap-southeast-1', 'coordinate': ['1.35', '103.82'], 'Status': 'PASS'},
    }   
        number_of_scanned_files = len(files_with_account_id)
        context = {
            'html_meter' : metre,
            'css_meter1' : css1*3.6,
            'css_meter2' : css2*3.6,
            'pass':pass_cnt,
            'fail':fail_cnt,
            'info':info_cnt,
            'total':total,
            'high':high_cnt,
            'low':low_cnt,
            'critical':critical_cnt,
            'medium':medium_cnt,
            'severities': json.dumps(result_list),
            'labels': labels,  # for pie chart
            'values': values,  # for pie chart
            'chart_div_service': chart_div_service,
            'chart_div': chart_div,
            'most_common_problem':most_common_problem_var,
            'common_issue_count':common_issue_count,
            'number_of_profiles':number_of_profiles,
            'number_of_scanned_files':number_of_scanned_files,
            "first_letter":first_letter+".png",
            'next_pass_cnt':next_pass_cnt,
            'next_fail_cnt':next_fail_cnt,
            'next_info_cnt':next_info_cnt,
            'next_total':next_total,
            'vector_map_dict':vector_map_dict
        }
    return render(request, 'dashboard.html',context)

# it shows the difference of status on dashboard 
def diff_between_scan(current_data,old_data):
    if current_data > old_data:
        data = current_data - old_data
    else:
        data = old_data - current_data
    return data



# ------------------------ Findings Data table -----------------------------------------
def findings(request):
    first_letter = get_profile_first_img(request)

    file_path = os.path.join(BASE_DIR, "output", request.session.get('current_json_file')) #set the current json file path in this data
    with open(file_path) as f:
        data = json.load(f)
    keys_to_extract = ['ServiceName', 'Status', 'Severity', 'ResourceType', 'ResourceDetails', 'Region', 'CheckTitle',
                       'RelatedUrl','AccountId','ResourceArn','CheckID','AssessmentStartTime','Risk']
    data_obj = [{key: item[key] for key in keys_to_extract} for item in data]
    filtered_data_list = data_obj

    # icons of tabular data ----------------------------------
    services_icon = {'accessanalyzer': 'accessanalyzer', 'account': 'account', 'athena': 'athena', 'backup': 'backup',
                     'cloudtrail': 'cloudtrail', 'cloudwatch': 'cloudwatch',
                     'config': 'config', 'drs': 'drs', 'ec2': 'ec2', 'emr': 'emr', 'glue': 'glue',
                     'guardduty': 'guardduty', 'iam': 'iam', 'inspector2': 'inspector2', 'macie': 'macie',
                     'network-firewall': 'network-firewall', 'organizations': 'organizations',
                     'resourceexplorer2': 'resourceexplorer2', 's3': 's3', 'securityhub': 'securityhub',
                     'ssm': 'ssm', 'trustedadvisor': 'trustedadvisor', 'support': 'support', 'vpc': 'vpc'}

    service_key = 'ServiceName'
    services_keys = get_json_data(service_key, data)
    print(services_keys)
    
    unique_keys = set(services_keys.keys()) - set(services_icon.keys())
    print("Unique Keys:", unique_keys)
    for key in unique_keys:
        services_icon[key] = key

    # Print the updated dictionary
    print(services_icon)

    status_key = 'Status'
    status_keys = get_json_data(status_key, data)

    region_key = 'Region'
    region_keys = get_json_data(region_key, data)

    severity_key = 'Severity'
    severity_keys = get_json_data(severity_key, data)
    
    
    context = {
        'filtered_data': filtered_data_list,
        'status_keys': status_keys,
        "region_keys": region_keys,
        'severity_keys': severity_keys,
        'services_keys': services_keys,
        'services_icon': services_icon,
        "first_letter":first_letter+".png",
    }
    return render(request,'findings-table.html',context)

# ------------------------------------ difference between files ------------------------------------
def difference_report(request):
    first_letter = get_profile_first_img(request)
    
    folder_path = os.path.join(BASE_DIR, 'output')
    all_files = os.listdir(folder_path)
    json_files = [file for file in all_files if file.endswith('.json') and not file.endswith('.ocsf.json')]
    
    filtered_files = [filename for filename in json_files if re.match(r'prowler-output-\d+-\d+\.json', filename)]
    # print("Filtered Files:", filtered_files)

    # Sort the files based on the extracted date and time
    sorted_files = sorted(filtered_files, key=extract_date_time)
    
    date_time_list = []
    
    for file_name in sorted_files:
        # Splitting the file name to extract the date and time
        date_time_str = file_name.split('-')[-1].split('.')[0]  # Extracting the last part and removing the extension
        
        # Extracting date and time components
        date_str = date_time_str[:8]
        time_str = date_time_str[8:]
        
        # Formatting to the desired format
        formatted_date_time = f"Date: {date_str[:4]}/{date_str[4:6]}/{date_str[6:]} Time: {time_str[:2]}:{time_str[2:4]}:{time_str[4:]}"
        
        # Appending to the list
        date_time_list.append(formatted_date_time)
  
    if request.method == "POST":
        first_file = request.POST.get('first-file')
        second_file = request.POST.get('second-file')
        
        try:
            first_file_date_str = first_file.split(' ')[1]
            first_file_time_str = first_file.split(' ')[3]
            
            second_file_date_str = second_file.split(' ')[1]
            second_file_time_str = second_file.split(' ')[3]
        
            for file in sorted_files:
                # Extracting date and time components from the file name
                date_time_str = file.split('-')[-1].split('.')[0]
                date_str = date_time_str[:4] + '/' + date_time_str[4:6] + '/' + date_time_str[6:8]
                time_str = date_time_str[8:10] + ':' + date_time_str[10:12] + ':' + date_time_str[12:]

                # Checking if the target date and time match
                if date_str == first_file_date_str and time_str == first_file_time_str:
                    first_file = file
                if date_str == second_file_date_str and time_str == second_file_time_str:
                    second_file = file
                    break
            else:
                print("Not found")
            
            first_file_data, first_file_all_data = get_all_data(first_file)
            second_file_data, second_file_all_data = get_all_data(second_file)
            
             # pie chart -------------------

            status_key = 'Status'
            first_file_status_counts = get_json_data(status_key, first_file_data)
            labels, values = pie_chart(first_file_status_counts)
            
            second_file_status_count = get_json_data(status_key, second_file_data)
            labels2, values2 = pie_chart(second_file_status_count)
            
            # utils_data = stack_status_diff(first_file_status_counts,second_file_status_count)
            # print(utils_data)
            
            # doghnut chart ------------------------
            
            first_file_result_list = doghnut_chart(first_file_data)
            second_file_result_list = doghnut_chart(second_file_data)
            
            
            context = {
                "first_letter":first_letter+".png",
                'files':date_time_list,
                'labels': labels,  # for pie chart
                'values': values,  # for pie chart
                'labels2':labels2,
                'values2':values2,
                'severities':first_file_result_list,
                'severities1':second_file_result_list,
                'first_file_all_data':first_file_all_data,
                'second_file_all_data':second_file_all_data
            }
            return render(request,'difference.html',context)
                    
        except IndexError:
            print("Invalid format, not enough elements.")
          
                
        return redirect('difference_report')
     
    context = {
        "first_letter":first_letter+".png",
        'files':date_time_list,    
    }
    return render(request,'difference.html',context)

# ---------------------------------- finding staus filter ----------------------------------------
def filter_status(request,field,value):
    first_letter = get_profile_first_img(request)
    file_path = os.path.join(BASE_DIR, "output", request.session.get('current_json_file')) #set the current json file path in this data
    with open(file_path) as f:
        data = json.load(f)
    keys_to_extract = ['ServiceName', 'Status', 'Severity', 'ResourceType', 'ResourceDetails', 'Region', 'CheckTitle',
                       'RelatedUrl','AccountId','ResourceArn','CheckID','AssessmentStartTime','Risk']
    
    # Extract only the data where 'Status' is 'Fail'
    filtered_data = [{key: item[key] for key in keys_to_extract} for item in data if item.get(field) == value]
    nonfilter_data = [{key: item[key] for key in keys_to_extract} for item in data if item.get('Status') != 'pass']
    filtered_data_list = filtered_data + nonfilter_data
   
    
    
    # icons of tabular data ----------------------------------
    services_icon = {'accessanalyzer': 'accessanalyzer', 'account': 'account', 'athena': 'athena', 'backup': 'backup',
                     'cloudtrail': 'cloudtrail', 'cloudwatch': 'cloudwatch',
                     'config': 'config', 'drs': 'drs', 'ec2': 'ec2', 'emr': 'emr', 'glue': 'glue',
                     'guardduty': 'guardduty', 'iam': 'iam', 'inspector2': 'inspector2', 'macie': 'macie',
                     'network-firewall': 'network-firewall', 'organizations': 'organizations',
                     'resourceexplorer2': 'resourceexplorer2', 's3': 's3', 'securityhub': 'securityhub',
                     'ssm': 'ssm', 'trustedadvisor': 'trustedadvisor', 'support': 'support', 'vpc': 'vpc'}
    service_key = 'ServiceName'
    services_keys = get_json_data(service_key, data)

    status_key = 'Status'
    status_keys = get_json_data(status_key, data)

    region_key = 'Region'
    region_keys = get_json_data(region_key, data)

    severity_key = 'Severity'
    severity_keys = get_json_data(severity_key, data)
    
    
    print(value)
    context = {
        'filtered_data': filtered_data_list,
        'status_keys': status_keys,
        "region_keys": region_keys,
        'severity_keys': severity_keys,
        'services_keys': services_keys,
        'services_icon': services_icon,
        'status_filter': value,
        "first_letter":first_letter+".png",
    }
    return context

# ------------------------------- status findings --------------------------------------

def pass_finding(request):
    field = "Status"
    status = "PASS"
    context = filter_status(request,field,status)
    return render(request,"findings-table.html",context)

def fail_finding(request):
    field = "Status"
    status = "FAIL"
    context = filter_status(request,field,status)
    return render(request,"findings-table.html",context)

def info_finding(request):
    field = "Status"
    status = "INFO"
    context = filter_status(request,field,status)
    return render(request,"findings-table.html",context)

def low_finding(request):
    field = "Severity"
    severity = "low"
    context = filter_status(request,field,severity)
    return render(request,"findings-table.html",context)

def medium_finding(request):
    field = "Severity"
    severity = "medium"
    context = filter_status(request,field,severity)
    return render(request,"findings-table.html",context)

def high_finding(request):
    field = "Severity"
    severity = "high"
    context = filter_status(request,field,severity)
    return render(request,"findings-table.html",context)

def critical_finding(request):
    field = "Severity"
    severity = "critical"
    context = filter_status(request,field,severity)
    return render(request,"findings-table.html",context)





# ------------------------------- AWS - CONFIG ----------------------------------------

def aws_config(request):
    if request.method == 'POST':
        user_name = request.user.username
        profil_name = request.POST.get('profile_name')
        accsess_key = request.POST.get('aws_accsess_key')
        secret_key = request.POST.get('aws_secret_key')
        regian = request.POST.get('dropdown')
        aws_accountid = get_aws_account_id(accsess_key, secret_key)
        print("prifile name  :", profil_name)
        print("accsess_key  :", accsess_key)

        if aws_accountid is not None:
            try:
                aws_modal_instance = Awsmodal.objects.create(user=request.user, aws_account_id=aws_accountid)
                aws_modal_instance.save()
                print("data was added")
                # aws_user_create.save()
                configure_aws_profiles(profil_name, accsess_key, secret_key, regian, output_format='json')
                
                iam_client = boto3.client('iam', aws_access_key_id=accsess_key, aws_secret_access_key=secret_key)
                try:
                    response = iam_client.get_user()
                    arn = response['User']['Arn']
                    account_id = arn.split(":")[4]
                except Exception as e:
                    print(f"Error: {e}")
                    print("Not found")
                
                command = f'prowler aws --profile {profil_name}'
                # command = 'prowler aws --list-checks'
                print("Scan startrd: ",command)
                # Create threads for each command
                thread1 = threading.Thread(target=run_cspm_command, args=(command,))
                
                #Start the threads
                thread1.start()
                #Wait for both threads to finish
                thread1.join()
                
                return redirect('dashboard')
            except Exception as e:
                print(e)
                print('data was not added')
        else:
            messages.error('invalid acess key and secret key')

    return render(request, 'aws-config.html')


# ------------------------------------- AWS NEW CONFIG FOR MULTY USER -------------------------------------

def aws_multiuser_config(request):
    first_letter = get_profile_first_img(request)
    if request.method == "POST":
        aws_username = request.POST.get('aws-user-name')
        aws_access_key = request.POST.get('acsess-key')
        aws_secret_key = request.POST.get('secter-key')
        aws_region = request.POST.get('region-dropdown')
        
        
        aws_accountid = get_aws_account_id(aws_access_key, aws_secret_key)
        if aws_accountid is not None:
            try:
                aws_modal_instance = Awsmodal.objects.create(user=request.user, aws_account_id=aws_accountid)
                aws_modal_instance.save()
                print("data was added")
                configure_aws_profiles(aws_username, aws_access_key, aws_secret_key, aws_region, output_format='json')
            except Exception as e:
                print(e)
                print('data was not added')
        else:
            messages.error(request,'invalid acess key and secret key')
            
        return redirect('dashboard')
    
    context = {
        "first_letter":first_letter+".png",
    }
        
    return render(request, 'aws-new-config.html',context)


# ------------------------------------- CLOUD NUMBER OF PROFILS ----------------------------------------------

def number_of_cloud_profiles(request):
    DIR_PATH = os.path.expanduser("~")
    FILE_PATH = os.path.join(DIR_PATH, ".aws", "credentials")
    section_name_lst = []
    try:
        with open(FILE_PATH, "r") as file:
            content = file.read()

        section_names = re.findall(r'\[(.*?)\]', content)
        print("Section names:")
        for section in section_names:
            section_name_lst.append(section)

    except FileNotFoundError:
        print(f"Error: File '{FILE_PATH}' not found.")
    except IOError:
        print(f"Error: Unable to read file '{FILE_PATH}'.")
        
    first_letter = get_profile_first_img(request)
    # Example usage
    profiles = read_aws_profiles()
    # print(f"profiles: {profiles}")
    profile_account_list = []
    # Iterate over the profiles and use credentials to create IAM client
    for profile, attributes in profiles.items():
        aws_access_key_id = attributes.get('aws_access_key_id')
        aws_secret_access_key = attributes.get('aws_secret_access_key')
        # print(f"access_key: {aws_access_key_id}, secret_key: {aws_secret_access_key}")
        
        # Check if access key and secret key are present
        if aws_access_key_id and aws_secret_access_key:
            iam_client = boto3.client('iam', aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)
 
            try:
                response = iam_client.get_user()
                arn = response['User']['Arn']
                account_id = arn.split(":")[4]
                #print(f'account_id: {account_id}')
                 # Append profile and account ID to the list as a dictionary
                profile_account_list.append({'profilename': profile, 'id': account_id})
            except Exception as e:
                print(f"Error: {e}")
                print("Not found")
        else:
            print("Access key or secret key is missing for IAM client.")
    # print(f"profile_list: {profile_account_list}")
    #get account id from template
    scan_progress = False
    if request.method == 'POST':
        account_id = request.POST.get('account-id',None)
        print(account_id)
        
        if account_id != "":
            scan_progress = True
            command = f'prowler aws --profile {account_id}'
            # command = 'prowler aws --'
            print("Scan startrd: ",command,scan_progress)
            # Create threads for each command
            thread1 = threading.Thread(target=run_cspm_command, args=(command,))
            #Start the threads
            thread1.start()
            #Wait for both threads to finish
            scan_progress = False
            thread1.join()
   
    context = {
        'profile_data':profile_account_list,
        "first_letter":first_letter+".png",
        'scan_progress': scan_progress,
    }
    print("This is account details: ",profile_account_list)
    return render(request, 'number-of-cloud-profiles.html',context)

# Define a function to run a command
def run_cspm_command(command):
    try:
        # Run the command using subprocess
        result = subprocess.run(command, shell=True, capture_output=True, text=True, check=True)

        # Process the result or perform other actions as needed

        print(f"Command executed successfully. Output: {result.stdout}")
    except subprocess.CalledProcessError as e:
        print(f"Error executing command. Output: {e.stderr}")
    except ImportError as e:
        print(f"Error importing module: {e}")
        # Handle the ImportError as needed



# ----------------------------------- read credentials file and get profile data ------------------------------------------
def read_aws_profiles():
    
    home_dir = os.path.expanduser('~')
    # Path to AWS credentials and config files
    credentials_path = os.path.expanduser(f'{home_dir}/.aws/credentials')
    config_path = os.path.expanduser(f'{home_dir}/.aws/config')

    aws_profiles = {}
    # Read AWS credentials file
    with open(credentials_path, 'r') as credentials_file:
        lines = credentials_file.readlines()
        current_profile = None
        for line in lines:
            if line.startswith('['):
                current_profile = line.strip('[]\n')
                aws_profiles[current_profile] = {}
            elif '=' in line and current_profile:
                key, value = line.strip().split(' = ')
                aws_profiles[current_profile][key] = value

   # Read AWS config file
    with open(config_path, 'r') as config_file:
        lines = config_file.readlines()
        current_profile = None
        for line in lines:
            if line.startswith('[profile '):
                current_profile = line.strip('[profile ]\n')
            elif '=' in line and current_profile:
                key, value = line.strip().split('=', 1)
                if current_profile not in aws_profiles:
                    aws_profiles[current_profile] = {}
                aws_profiles[current_profile][key.strip()] = value.strip()
    return aws_profiles

    


# ------------------------------------- SCAN HISTORY -------------------------------------------------------


def scan_history_view(request):
    first_letter = get_profile_first_img(request)
    user_id_main = request.user.id

    folder_path = os.path.join(BASE_DIR, 'output')
    all_files = os.listdir(folder_path)
    json_files = [file for file in all_files if file.endswith('.json') and not file.endswith('.ocsf.json')]

    # Filter the list to include only files with the specified format
    filtered_files = [filename for filename in json_files if re.match(r'prowler-output-\d+-\d+\.json', filename)]
    # print("Filtered Files: ", filtered_files)

    # Sort the files based on the extracted date and time
    sorted_files = sorted(filtered_files, key=extract_date_time)
    # print("Sorted Files:", sorted_files)

    # Extract User Account IDs from filenames
    # Extract user_acc_id from filenames
    user_acc_id = [re.search(r'prowler-output-(\d+)-', filename).group(1) for filename in sorted_files]
    # print(f'sorted files: {sorted_files}')
    
    # Get the user's AWS accounts
    user_aws_accounts = Awsmodal.objects.filter(user=request.user)
    aws_account_ids = [aws_account.aws_account_id for aws_account in user_aws_accounts]
    print(aws_account_ids)


    # List to store dictionaries for files with date and time information
    files_with_date_time = []

    # Create a set to store unique identifiers for files
    unique_files = set()

    # Iterate over each AWS account ID
    for account_id in aws_account_ids:
        # Create a list of dictionaries for files with matching user_acc_id
        files_for_account = [
            {
                'acc_id': user_acc_id[i],
                'name': filename,
                'date': extract_date_time(filename).strftime('%Y-%m-%d'),
                'date_time': extract_date_time(filename),
                'time': extract_date_time(filename).strftime('%H:%M:%S'),
            }
            for i, filename in enumerate(sorted_files)
            if user_acc_id[i] == account_id
        ]

        # Add unique files to the main list and the set
        for file_dict in files_for_account:
            unique_id = (file_dict['name'], file_dict['date'], file_dict['time'])
            if unique_id not in unique_files:
                file_dict['number'] = len(files_with_date_time) + 1
                files_with_date_time.append(file_dict)
                unique_files.add(unique_id)

    # Sort data based on the 'date_time' key
    sorted_data = sorted(files_with_date_time, key=lambda x: x['date_time'], reverse=True)
    # print("All fileS: ",files_with_date_time)

    #sort files according to it's date and time    
    name_dict_list = [{'name': entry['name']} for entry in files_with_date_time]
                
                    
    # Now 'files_with_date_time' contains dictionaries for all files with matching AWS account IDs

    # Assuming 'request' is the Django request object
    if request.method == "POST":
        file_name = request.POST.get('file-name')
        request.session['file_from_history'] = file_name
        
        if request.session.get('file_from_history') is not None:
            print("Current file name: ",request.session.get('file_from_history'))
            # print("All files: ",name_dict_list)
            # Example: Get the "before" file for the current file
            current_file_name = request.session.get('file_from_history')
            current_account_id = current_file_name.split('-')[2]
            print(current_account_id)
            
            for i,file in enumerate(name_dict_list):
                if current_file_name == file['name']:
                    print(i)
                    next_index = i - 1
                    print(next_index)
                    # next_file_dict = name_dict_list[next_index] if next_index < len(name_dict_list) else None
                    if next_index < len(name_dict_list):
                        next_file_dict = name_dict_list[next_index]
                        next_account_id = next_file_dict['name'].split('-')[2]
                        print(next_account_id)
                        if current_account_id == next_account_id:
                            request.session['next_file_from_selected_file'] = next_file_dict['name']
                            print(request.session.get("next_file_from_selected_file"))
                            break
                            
                        else:
                            print("This is first else condition")
                            print(current_file_name)
                            request.session['next_file_from_selected_file'] = current_file_name
                            
                    else:
                        print("This is second else condition")
                        request.session['next_file_from_selected_file'] = current_file_name
        return redirect('dashboard')
        
    # Increment the counter separately
    # for item in files_with_date_time:
    #     count += 1
    #     item['number'] = count
    # print("Files with Date Time:", files_with_date_time)
    

    context = {
        'files_with_date_time': sorted_data,
        "first_letter":first_letter+".png",
    }
    return render(request, 'scan-history.html', context)

def extract_date_time(filename):
    match = re.search(r'-(\d{14})\.json', filename)
    if match:
        date_time_str = match.group(1)
        date_time_obj = datetime.strptime(date_time_str, '%Y%m%d%H%M%S')
        return date_time_obj
    else:
        return None
            
# Define a custom sorting key using the date and time information
def sorting_key(file_name):
    # Use regular expression to find the date and time part
    match = re.search(r'\d{14}', file_name)
    
    if match:
        date_time_part = match.group()
        return datetime.strptime(date_time_part, "%Y%m%d%H%M%S")
    else:
        # Handle cases where the date and time format is not found
        return datetime.min

# ---------------------------------------- PDF GANRARION ------------------------------------

def dynamic_pdf_ganrate(request):
    # dynamic json file
    # folder_path = os.path.join(BASE_DIR, 'prowler_app/output/prowler-output-891377055878-20240215180534.json')
    # with open(folder_path) as f:
    #     print()
    #     data = json.load(f)
    # keys_to_extract = ['ServiceName', 'Status', 'Severity', 'ResourceType', 'ResourceDetails', 'Region', 'CheckTitle',
    #                    'RelatedUrl']
    # data_obj = [{key: item[key] for key in keys_to_extract} for item in data]

    html_content = render_to_string('pdf-templet.html', {})
    print(html_content)

    call()
    with open('data.html', 'w') as htmldata:
        htmldata.write(html_content)
    jsonname = 'name'
    output = run_command('nayan')
    print(output)
    with open("C:\\Users\\vekar\\PycharmProjects\\invensense\\prowler_app\\pdffiles\\result.pdf", "rb") as f:
        response = HttpResponse(f.read(), content_type='application/pdf')
        response['Content-Disposition'] = 'inline; filename={}.pdf'.format(jsonname)
    return response






# ---------------------------------------EMIL VLIDAITION ----------------------------

def is_valid_email(email):
    """
    Validate an email address using Django's built-in email validation.

    Args:
    - email (str): The email address to be validated.

    Returns:
    - bool: True if the email is valid, False otherwise.
    """
    try:
        # Use Django's validate_email function
        validate_email(email)
        return True
    except ValidationError:
        # ValidationError will be raised if the email is not valid
        return False

    # --------------------------  PASSWORD VALIDATION --------------------------------------


def is_valid_password(password):
    """
    Validate a password using Django's built-in validators.

    Args:
    - password (str): The password to be validated.

    Returns:
    - bool: True if the password is valid, False otherwise.
    """
    # Use Django's built-in validators
    validators = [MinimumLengthValidator(), CommonPasswordValidator(), NumericPasswordValidator()]

    # Validate the password
    try:
        for validator in validators:
            validator.validate(password)
    except ValidationError as e:
        # If any validation fails, print the error message and return False
        print(e)
        return False

    # If all validations pass, return True
    return True


# --------------------------  USER VALIDATION --------------------------------------


def is_user_exists(username):
    """
    Check if a user with the given username already exists.

    Args:
    - username (str): The username to check.

    Returns:
    - bool: True if the user exists, False otherwise.
    """
    return User.objects.filter(username=username).exists()


# -------------------------- AWS ACCOUNT ID ----------------------------------------

def get_aws_account_id(access_key, secret_key):
    # Create an IAM client
    iam_client = boto3.client('iam', aws_access_key_id=access_key, aws_secret_access_key=secret_key)

    # Get user information to obtain account ID
    try:
        response = iam_client.get_user()
        arn = response['User']['Arn']
        account_id = arn.split(":")[4]
        return account_id
    except Exception as e:
        print(f"Error: {e}")
        return None

def configure_aws_profiles(profile_name, access_key, secret_key, region = "us-west-1", output_format = "json"):
    aws_folder = os.path.expanduser('~/.aws')
    credentials_path = os.path.join(aws_folder, 'credentials')
    config_path = os.path.join(aws_folder, 'config')
    
    # Create the ~/.aws folder if it doesn't exist
    if not os.path.exists(aws_folder):
        os.makedirs(aws_folder)
    
    global AWS_ACCOUNT_COUNT
    AWS_ACCOUNT_COUNT += 1
    
    # Create or update AWS credentials file
    with open(credentials_path, 'a') as credentials_file:
        credentials_file.write(f"\n[{profile_name}]")
        credentials_file.write(f"\naws_access_key_id = {access_key}")
        credentials_file.write(f"\naws_secret_access_key = {secret_key}")
        
    # Create or update AWS config file
    with open(config_path, 'a') as config_file:
        config_file.write(f"\n[profile {profile_name}]")
        config_file.write(f"\nregion =  {region}")
        config_file.write(f"\noutput = {output_format}")
    
    print(f"AWS profile '{profile_name}' has been configured.")


def count_aws_profiles():
    credentials_path = os.path.expanduser('~/.aws/credentials')
    profiles_count = 0

    # Check if the AWS credentials file exists
    if os.path.isfile(credentials_path):
        with open(credentials_path, 'r') as credentials_file:
            lines = credentials_file.readlines()

            # Count the number of profiles by identifying sections [profile profile_name]
            for line in lines:
                if line.startswith('[') and line.endswith(']\n'):
                    profiles_count += 1

    return profiles_count

# ------------------------------------- GET DATA FROM JSON FILE -----------------------------------------


def get_json_data(key, data):
    keys_to_extract = ['ServiceName', 'Status', 'Severity', 'ResourceType', 'ResourceDetails', 'Region', 'CheckTitle',
                        'RelatedUrl']
    data_obj = [{key: item[key] for key in keys_to_extract} for item in data]

    json_key_data = {}
    for entry in data_obj:
        region = entry.get(key)
        if region:
            json_key_data[region] = json_key_data.get(region, 0) + 1
    return json_key_data


# ------------------------------------- PDF CONVETOR FUNCTION -----------------------------------------------
def run_command(name):
    try:
        command = r'wkhtmltopdf --collate data.html "C:\\Users\\vekar\\PycharmProjects\\prowler_dynamic\\prowler_app\\pdffiles\\{}.pdf"'.format(
                name)
        # Execute the command
        result = subprocess.run(command, shell=True, capture_output=True, text=True)

            # Check if the command executed successfully
        if result.returncode == 0:
            return result.stdout
        else:
            return f"Error executing command: {result.stderr}"
    except Exception as e:
        return f"Error: {str(e)}"