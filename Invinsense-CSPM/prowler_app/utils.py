from collections import Counter
import pandas as pd  # Used to handle dataframes
import plotly.express as px
import json
import os
from invinsense_cspm.settings import BASE_DIR



def doghnut_chart(data):
    severities_lst = [item['Severity'] for item in data]
    severities_lable_count = Counter(severities_lst)
    low_count = severities_lable_count['low']
    medium_count = severities_lable_count['medium']
    high_count = severities_lable_count['high']
    critical_count = severities_lable_count['critical']
    result_list = [low_count, medium_count, high_count, critical_count]
    return result_list

def azure_doghnut_chart(data):
    danger_count = data['danger']
    warning_count = data['warning']
    good_count = data['good']
    
    result_list = [danger_count, warning_count, good_count]
    return result_list

def pie_chart(value):
    status_counts = value
    labels = list(status_counts.keys())
    values = list(status_counts.values())
    return labels, values


def line_chart(data):
    region_counts = {}
    for entry in data:
        reg = entry.get('Region')
        if reg:
            region_counts[reg] = region_counts.get(reg, 0) + 1
        # line chart =======
    region_labels = list(region_counts.keys())
    region_values = list(region_counts.values())
    return region_labels, region_values


def bar_chart(data):
    services = [item['ServiceName'] for item in data]
    counter = Counter(services)
    top_10 = counter.most_common(10)
    first_elements = [tup[0] for tup in top_10]
    top_10_services = []
    for service in services:
        for ls in first_elements:
            if service == ls:
                top_10_services.append(ls)
    other_services = [item for item in services if item not in top_10_services]
    return top_10_services, other_services

def stack_azure_severity(data):
     # Flatten the nested structure and create a list of dictionaries
    flattened_data = [{'Service': key, **value} for item in data for key, value in item.items()]

    # Create a pandas DataFrame
    df = pd.DataFrame(flattened_data)

    # Define the color mapping for each metric
    color_discrete_map = {
        'checked_items': '#58D68D',    # Green
        'flagged_items': '#5DADE2',    # Blue
        'resources_count': '#F47B3F',  # Orange
        'rules_count': '#EC7063'       # Red
    }

    # Create the stacked bar chart using Plotly Express
    fig = px.bar(df, x="Service", y=["checked_items", "flagged_items", "resources_count", "rules_count"],
                 color_discrete_map=color_discrete_map,
                 labels={"value": "Value", "variable": "Metric"})

    fig.update_layout(
        autosize=True,
        margin=dict(l=0, r=0, b=0, t=30),
        paper_bgcolor="white",
    )

    chart_div = fig.to_html(full_html=False)

    return chart_div

def stack_bar_region(data):
    filtered_data = [entry for entry in data if entry.get('Status') == 'FAIL']

    # Extract region and severity from filtered data
    result = [{'Region': entry.get('Region'), 'Severity': entry.get('Severity'), 'Status': entry.get('Status')} for
              entry in filtered_data]

    # Create a dictionary to store counts for each region and severity
    region_severity_counts = {}

    # Count occurrences of each region and severity
    for entry in data:
        region = entry['Region']
        severity = entry['Severity']

        if region not in region_severity_counts:
            region_severity_counts[region] = {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}

        region_severity_counts[region][severity] += 1

    # Convert the region_severity_counts dictionary to a list of lists
    result_list = []  # Header

    for region, severity_counts in region_severity_counts.items():
        for severity, count in severity_counts.items():
            result_list.append([region, severity, count])

    # print(result_list)
    # Create the pandas DataFrame
    df = pd.DataFrame(result_list, columns=['Region', 'Severity', 'Value'])
    # print dataframe.
    # print(df)

    fig = px.bar(df, x="Region", y="Value", color="Severity",
                 text_auto=True,
                 color_discrete_map={
                     'low': '#1CB40F',
                     'medium': '#3498DB',
                     'high': '#EA8F1B',
                     'critical': '#EF1E1B'
                 })

    fig.update_layout(
        autosize=True,
        margin=dict(l=0, r=0, b=0, t=30),
        paper_bgcolor="white",
    )

    chart_div = fig.to_html(full_html=False)

    return chart_div

def stack_status_diff(first_data,second_data):
    first_file_filter_data = [entry for entry in first_data if entry.get('Status') == 'FAIL']
    second_file_filter_data = [entry for entry in second_data ]
    
    first_result = [
        {'ServiceName': entry.get('ServiceName'), 'Severity': entry.get('Severity'), 'Status': entry.get('Status')} for
        entry in first_file_filter_data]
    
    second_result = [
        {'ServiceName': entry.get('ServiceName'), 'Severity': entry.get('Severity'), 'Status': entry.get('Status')} for
        entry in second_file_filter_data]
    
    Status_count = {}
    result = first_result + second_result
    for entry in first_data:
        Status = entry['Status']
        
        if Status not in Status_count:
            Status_count[Status] = {'FAIL' : 0, 'PASS': 0, 'INFO': 0}
        Status_count[Status] += 1
    
    return first_result
    
    
    
def stack_bar_service(data):
    filtered_data = [entry for entry in data if entry.get('Status') == 'FAIL']

    # Extract region and severity from filtered data
    result = [
        {'ServiceName': entry.get('ServiceName'), 'Severity': entry.get('Severity'), 'Status': entry.get('Status')} for
        entry in filtered_data]

    # Create a dictionary to store counts for each region and severity
    ServiceName_severity_counts = {}

    # Count occurrences of each region and severity
    for entry in data:
        ServiceName = entry['ServiceName']
        severity = entry['Severity']

        if ServiceName not in ServiceName_severity_counts:
            ServiceName_severity_counts[ServiceName] = {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}

        ServiceName_severity_counts[ServiceName][severity] += 1

    # Convert the region_severity_counts dictionary to a list of lists
    result_list = []  # Header

    for ServiceName, severity_counts in ServiceName_severity_counts.items():
        for severity, count in severity_counts.items():
            result_list.append([ServiceName, severity, count])

    # print(result_list)
    # Create the pandas DataFrame
    # Assuming 'result_list' is your data
    df = pd.DataFrame(result_list, columns=['Service Name', 'Severity', 'Value'])

    # Create Plotly chart with responsive settings
    fig = px.bar(df, x="Service Name", y="Value", color="Severity",
                 text_auto=True,
                 color_discrete_map={
                     'low': '#1CB40F',
                     'medium': '#3498DB',
                     'high': '#EA8F1B',
                     'critical': '#EF1E1B'
                 })

    # Update layout for responsiveness
    fig.update_layout(
        autosize=True,
        margin=dict(l=0, r=0, b=0, t=30),
        paper_bgcolor="white",
    )

    # Convert the Plotly chart to HTML
    chart_div_service = fig.to_html(full_html=False)

    return chart_div_service


def most_common_problem(data):
    check_title_severity_counts = {}

    # Count occurrences of each CheckTitle and Severity
    for entry in data:
        check_title = entry['CheckTitle']
        severity = entry['Severity']

        key = (check_title, severity)

        if key not in check_title_severity_counts:
            check_title_severity_counts[key] = 0

        check_title_severity_counts[key] += 1

    # Sort the dictionary based on count in descending order
    sorted_counts = sorted(check_title_severity_counts.items(), key=lambda x: x[1], reverse=True)

    # Get the top 10 records
    top_10 = sorted_counts[:10]

    # Print the structured format for the top 10 records
    result_list = []

    for (check_title, severity), count in top_10:
        result_list.append({'CheckTitle': check_title, 'Count': count, 'Severity': severity})

    return result_list


#-------------------------------- check json file ---------------------------------------------------
def refactor_json(filepath):
    # Specify the path to your JSON file
    json_file_path = filepath

    # Step 1: Read the content of the JSON file
    with open(json_file_path, 'r') as file:
        content = file.read()

    # Step 2: Remove the trailing ',' character (if present)
    content = content.rstrip(',')
    if content and content[-1] != ']':
        content += ']'  # Add ',' if there are still items in the JSON array

    # Step 3: Append ']' at the end of the modified content
    else:
        content += ''

    # Step 4: Write the updated content back to the JSON file
    with open(json_file_path, 'w') as file:
        file.write(content)
    
    return print("File is Refactored")

def get_all_data(file_name):
    file_path = os.path.join(BASE_DIR, "output", file_name)
    print(file_name)
    refactor_json(file_path)
    with open(file_path) as f:
        first_file_data = json.load(f)
    keys_to_extract = ['ServiceName', 'Status', 'Severity', 'ResourceType', 'ResourceDetails', 'Region', 'CheckTitle',
                    'RelatedUrl']
    next_file_data_obj = [{key: item[key] for key in keys_to_extract} for item in first_file_data]
    return next_file_data_obj, first_file_data