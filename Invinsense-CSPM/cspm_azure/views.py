from django.shortcuts import render
from prowler_app.views import *
import json, subprocess, shutil

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def azure_dashboard(request):
    first_letter = get_profile_first_img(request)
    # print(request.user.username)
    
    file = "scoutsuite_results_azure-tenant-48bc2d88-682b-4a91-ac9d-c1851a7dbe97.json"
    file_path = os.path.join(BASE_DIR, "output", file)
    with open(file_path) as f:
        data = json.load(f)
    
    # gives you a severity from data ----------------------------------
    summary = data['last_run']['summary']
    summary_lst = list(summary.values())
    danger = 0
    warning = 0
    good = 0
    level_dict = {}
    for entry in summary_lst:
        if entry['max_level'] == "danger":
            danger += 1
        elif entry['max_level'] == "warning":
            warning += 1
        else:
            good += 1
    level_dict['danger'] = danger
    level_dict['warning'] = warning
    level_dict['good'] = good
    
    # for donut chart ------------------------
    result_list = azure_doghnut_chart(level_dict)
    
    filter_service_name = [{key:value} for key, value in data['last_run']['summary'].items()]
    chart_div_azure_services = stack_azure_severity(filter_service_name)
    fetched_data_list = []
    
    for service, details in data["services"].items():
        for finding_key, finding_details in details["findings"].items():
            fetched_data_list.append({
                "service": service,
                "finding": finding_key,
                "description": finding_details['description'],
                "flagged_item": finding_details['flagged_items'],
                "checked_item": finding_details['checked_items'],
                "level": finding_details['level'],
                "service_name": finding_details['service']
            })
    levels = [item['level'] for item in fetched_data_list]
    
    # Count the occurrences of each level
    level_counts = Counter(levels)

    # Count the occurrences of each level
    level_counts = Counter(levels)

    # Convert the Counter to a dictionary
    level_counts_dict = dict(level_counts)
    total = sum(level_counts_dict.values())
     
    
    # Filter data where level is 'warning'
    filtered_data = [entry for entry in fetched_data_list if entry['level'] == 'warning']
    # Example: Fetching data for virtualmachines
    meta_data = data["metadata"]
    meta_data_lst = list(meta_data)
    
    cnt = 0
    for entry in meta_data:
        for entry_lst in meta_data_lst:
            if entry == entry_lst :
                cnt += 1
    
    user_data = data['services']["aad"]
    
    fetched_user_data_list = []

    for index, (user_name, user_data) in enumerate(data["services"]["aad"]["users"].items(), start=1):
        fetched_user_data_list.append({
            "index": index,
            "user_name": user_name,
            "user_id": user_data["id"],
            "display_name": user_data["display_name"],
            "mail": user_data["mail"],
            "user_type": user_data.get("user_type", ""),  # Using get to handle missing key
            "surname": user_data.get("surname", ""),  # Using get to handle missing key
        })
        
    context = {
        "azure":"azure",
        "first_letter":first_letter+".png",
        'max_level':json.dumps(result_list),
        'danger':level_counts_dict['danger']  if 'danger' in level_counts_dict else 0,
        'warning':level_counts_dict['warning']  if 'warning' in level_counts_dict else 0,
        'good':level_counts_dict['good'] if 'good' in level_counts_dict else 0,
        'total':total,
        'chart_div_azure_services':chart_div_azure_services,
        'fetched_data_list':fetched_data_list,
        'table_head':meta_data_lst,
        'table_data':meta_data,
        'user_data':user_data,
        'fetched_user_data_list':fetched_user_data_list,
    }
    return render(request,'azure-dashboard.html',context)

# ------------------------ Findings Data table -----------------------------------------
def azure_findings(request):
    first_letter = get_profile_first_img(request)
    
    file = "scoutsuite_results_azure-tenant-48bc2d88-682b-4a91-ac9d-c1851a7dbe97.json"
    file_path = os.path.join(BASE_DIR, "output", file)
    with open(file_path) as f:
        data = json.load(f)
    
    fetched_data_list = []
    for service, details in data["services"].items():
        for finding_key, finding_details in details["findings"].items():
            fetched_data_list.append({
                "service": service,
                "finding": finding_key,
                "description": finding_details['description'],
                "flagged_item": finding_details['flagged_items'],
                "checked_item": finding_details['checked_items'],
                "level": finding_details['level'],
                "service_name": finding_details['service'],
                "path": finding_details['path'],
                "rationale": finding_details['rationale'],
                "references": finding_details['references'],
                "compliance": finding_details['compliance'],
            })
    
    key = 'level'
    levels = get_json_data(key, data)  
    
    key = 'service'
    services = get_json_data(key, data) 

    context = {
        "azure":"azure",
        "first_letter":first_letter+".png",
        'fetched_data_list':fetched_data_list,
        'levels':levels,
        'services':services,
    }
    return render(request,'azure-findings.html',context)

#------------------------------------------------- findings by levels -----------------------------------------
def level_filter(request, level):
    first_letter = get_profile_first_img(request)
    
    file = "scoutsuite_results_azure-tenant-48bc2d88-682b-4a91-ac9d-c1851a7dbe97.json"
    file_path = os.path.join(BASE_DIR, "output", file)
    with open(file_path) as f:
        data = json.load(f)
    
    matched_data = []
    for service, details in data["services"].items():
        for finding_key, finding_details in details["findings"].items():
            if finding_details['level'] == level:
                matched_data.append({
                    "service": service,
                    "finding": finding_key,
                    "description": finding_details['description'],
                    "flagged_item": finding_details['flagged_items'],
                    "checked_item": finding_details['checked_items'],
                    "level": finding_details['level'],
                    "service_name": finding_details['service'],
                    "path": finding_details['path'],
                    "rationale": finding_details['rationale'],
                    "references": finding_details['references'],
                    "compliance": finding_details['compliance'],
                })
                
    unmatched_data = []
    for service, details in data["services"].items():
        for finding_key, finding_details in details["findings"].items():
            if finding_details['level'] != level:
                unmatched_data.append({
                    "service": service,
                    "finding": finding_key,
                    "description": finding_details['description'],
                    "flagged_item": finding_details['flagged_items'],
                    "checked_item": finding_details['checked_items'],
                    "level": finding_details['level'],
                    "service_name": finding_details['service'],
                    "path": finding_details['path'],
                    "rationale": finding_details['rationale'],
                    "references": finding_details['references'],
                    "compliance": finding_details['compliance'],
                })
    fetched_data_list = matched_data + unmatched_data
    key = 'level'
    levels = get_json_data(key, data)  
    
    key = 'service'
    services = get_json_data(key, data) 
    
    context = {
        "azure":"azure",
        "first_letter":first_letter+".png",
        'fetched_data_list':fetched_data_list,
        'levels':levels,
        'services':services,
        'level_filter': level,
    }
    return context

def findings_good(request):
    first_letter = get_profile_first_img(request)
    key = 'good'
    context = level_filter(request,key)
    
    return render(request,'azure-findings.html',context)

def findings_warning(request):
    first_letter = get_profile_first_img(request)
    key = 'warning'
    context = level_filter(request,key)
    
    return render(request,'azure-findings.html',context)

def findings_danger(request):
    first_letter = get_profile_first_img(request)
    key = 'danger'
    context = level_filter(request,key)
    
    return render(request,'azure-findings.html',context)

#------------------------------------------------- get jason data from scoutsuite file ----------------------------------------------
def get_json_data(key, data):
    lst=[]
    for service, details in data['services'].items():
        for finding_key, finding_details in details['findings'].items():
            lst.append({
                key: finding_details[key],
            })

    # Extract unique 'level' values using a set
    unique_values = set(item[key] for item in lst)

    # Convert the set to a list if needed
    unique_values_list = list(unique_values)

    return unique_values_list


def azure_cloud_profiles(request):
    first_letter = get_profile_first_img(request)
    user_data = []

    try:
        # Run the command to get Azure account list
        
        command = "az account list --all"
        result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        # Check if result.stdout is an empty list
        if result.stdout.strip() == "[]":

            # Run both commands sequentially
            commands = ["az login", "az account list --all"]
            for command in commands:
                result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                if result.returncode != 0:
                    print(f"Error executing command '{command}': {result.stderr}")
        # Parse the JSON response
        try:
            json_data = json.loads(result.stdout)
            user_data = [
                {
                    "cloudName": item['cloudName'],
                    "subscriptionName": item['name'],
                    "tenantID": item['tenantId'],
                    "isDefault": item['isDefault'],
                    "userName": item['user']['name'],
                }
                for item in json_data
            ]
        except json.JSONDecodeError:
            print("Error parsing JSON response.")

        # Check the return code to see if the command was successful
        if result.returncode == 0:
            print("\nCommand executed successfully.")

            # Handle POST request
            if request.method == "POST":
                tenant_id = request.POST.get('tenent-id', None)
                print("Tenant ID:", tenant_id)

                if tenant_id:
                    try:
                        # Change Azure profile
                        # profile_result = change_azure_profile(tenant_id)

                        # scan_thread = threading.Thread(target=run_scan_command, args=(tenant_id,))
                        # scan_thread.start()
                        run_scan_command(tenant_id)

                        # Wait for the thread to complete
                        # scan_thread.join()

                        # Run move_azure_files only if scan_thread completed successfully
                        # if scan_thread.is_alive():
                        #     print("Scan thread is still running.")
                        
                        # else:
                        # source_directory = os.path.join(BASE_DIR, "scoutsuite-report", "scoutsuite-results")
                        # input_file_path = os.path.join(source_directory, f"scoutsuite_results_azure-tenant-{tenant_id}.js")
                        # output_file_path = os.path.join(source_directory, f"scoutsuite_results_azure-tenant-{tenant_id}.json")
                        # convert_js_to_json(input_file_path,output_file_path)
                        # print("File converted successfully")
                        # # move_azure_files(tenant_id)
                        # print("Move completed successfully.")

                    except Exception as e:
                        print(f"An error occurred: {e}")
                else:
                    print("No tenant ID provided.")
        else:
            print(f"\nCommand failed with return code {result.returncode}.")

    except Exception as e:
        print(f"An error occurred: {e}")

    context = {
        "azure": "azure",
        "first_letter": f"{first_letter}.png",
        'user_data': user_data,
    }
    return render(request, 'azure-profiles.html', context)

def run_scan_command(tenant_id):
    print(f"scout azure --tenant {tenant_id} --user-account-browser")
    try:
        scan_command = 'scout azure --cli'
        # scan_command = f"scout azure --tenant {tenant_id} --user-account-browser"
        scan_result = subprocess.run(scan_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        print(f'output: {scan_result.stdout}')
        print(f'error: {scan_result.stderr}')
        print(f'run command: {scan_command}')
        print("tenant id: ", tenant_id)
    except Exception as e:
        print(f"An error occurred in run_scan_command: {e}")
    else:
        print("run_scan_command terminated successfully.")
        
def convert_js_to_json(input_file_path,output_file_path):
    with open(input_file_path) as f:
        json_payload = f.readlines()
        json_payload.pop(0)
        json_payload = ''.join(json_payload)
        json_file = json.loads(json_payload)
    with open(output_file_path, 'w') as outfile:
        json.dump(json_file, outfile, indent = 4)
    

def move_azure_files(tenant_id):
    source_directory = os.path.join(BASE_DIR, "scoutsuite-report", "scoutsuite-results")
    destination_directory = r"D:/infopercept/CSPM/invinsense-cspm/output"
    
    now = datetime.datetime.now()
    date_time_str = now.strftime("%Y-%m-%d_%H-%M-%S")

    source_path = os.path.join(source_directory, f"scoutsuite_results_azure-tenant-{tenant_id}.json")
    destination_path = os.path.join(destination_directory, f"scoutsuite_results_azure-tenant-{tenant_id}_{date_time_str}.json")
    

    if os.path.exists(source_path):
        shutil.move(source_path, destination_path)
        print(f"File moved successfully from {source_path} to {destination_path}")
    else:
        print(f"Source file {source_path} does not exist.")
        
        
def load_json_from_file(input_file_path, output_file_path):
    with open(input_file_path) as input_file:
        # Read all lines except the first one
        json_payload = ''.join(input_file.readlines()[1:])
        # Load JSON from the payload
        json_file = json.loads(json_payload)

    with open(output_file_path, 'w') as output_file:
        # Write formatted JSON to the output file
        json.dump(json_file, output_file, indent=4)
        
def change_azure_profile(tenant_id):
    """
    Change Azure profile with the given tenant ID.
    """
    command_change_profile = f"az login --tenant {tenant_id} --allow-no-subscriptions"
    profile_result = subprocess.run(command_change_profile, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    print("Result",profile_result.stdout)
    print("Error",profile_result.stderr)
    
    print(command_change_profile)
    return profile_result



def azure_cloud_profiles2(request):
    first_letter = get_profile_first_img(request)
    user_data = []
    
    account_list_command = 'az account list'
    result = subprocess.run(account_list_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    print(f'account list o/p: {result.stdout}')
    print(f'account list error: {result.stderr}')
    json_data = json.loads(result.stdout)
    user_data = [
        {
            "cloudName": item['cloudName'],
            "subscriptionName": item['name'],
            "tenantID": item['tenantId'],
            "isDefault": item['isDefault'],
            "userName": item['user']['name'],
        }
        for item in json_data
    ]
    
    if request.method == "POST":
        tenant_id = request.POST.get('tenent-id', None)
        print("Tenant ID:", tenant_id)
        
        if tenant_id is not None:
            profile_change_command = f"az login --tenant {tenant_id} --allow-no-subscriptions"
            profile_result = subprocess.run(profile_change_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            print("Result",profile_result.stdout)
            print("Error",profile_result.stderr)
            
            if profile_result.stdout is not None:
                scan_command = 'scout azure --cli'
                scan_result = subprocess.run(scan_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                print(f'output: {scan_result.stdout}')
                print(f'error: {scan_result.stderr}')         
    
    context = {
        "azure": "azure",
        "first_letter": f"{first_letter}.png", 
        'user_data': user_data,
    }
    
    return render(request, 'azure-profiles.html',context)

# Create your views here.
