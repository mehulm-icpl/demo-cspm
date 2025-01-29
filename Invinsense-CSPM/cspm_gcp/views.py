from django.shortcuts import render
from prowler_app.views import get_profile_first_img
import os, json
from django.conf import settings
from .utils import *

def dashboard(request):
    first_letter = get_profile_first_img(request)
    
    file_name = "scoutsuite_results_gcp-dogwood-reality-354304.json"
    file_path = os.path.join( settings.BASE_DIR , 'output', file_name )
    
    with open(file_path, 'r') as f:
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
    result_list = gcp_doghnut_chart(level_dict)
    
    filter_service_name = [{key:value} for key, value in data['last_run']['summary'].items()]
    chart_div_azure_services = gcp_azure_severity(filter_service_name)
    fetched_data_list = []
    
    
    context = {
        'gcp':'gcp',
        "first_letter": f"{first_letter}.png",
        'chart_div_azure_services':chart_div_azure_services,
        'donutchart':json.dumps(result_list),
    }
    return render(request,'gcp-dashboard.html',context)


def findings(request):
    first_letter = get_profile_first_img(request)
    
    file_name = "scoutsuite_results_gcp-dogwood-reality-354304.json"
    file_path = os.path.join( settings.BASE_DIR , 'output', file_name )
    
    with open(file_path, 'r') as f:
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
        'gcp':'gcp',
        "first_letter": f"{first_letter}.png",
        'fetched_data_list':fetched_data_list,
        'services':services,
        'levels':levels,
    }
    return render(request,'gcp-findings.html',context)

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

# Create your views here.
