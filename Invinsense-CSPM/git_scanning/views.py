import subprocess
from django.conf import settings
from django.http import HttpResponse
from pygments.lexers import go
import threading
from datetime import datetime
import json
import os
import re
import time
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from collections import Counter
import plotly.graph_objects as go
from django.template.loader import render_to_string

import boto3
from prowler_app.views import get_profile_first_img



# Create your views here.


# ------------------------------- GIT SCANER -------------------------------------

@login_required
def git_leaks_data(request):
    if request.method == 'POST':
        repo_type = request.POST.get('visibility')
        git_username = request.POST.get('username')
        git_url = request.POST.get('git_url')
        access_tocken = request.POST.get('token')
        current_datetime = get_current_date_and_time()
        name = get_repository_name_from_url(git_url)
        print(name)
        scan_prosses = False
        if git_username is not None and git_url is not None:
            try:

                scan_prosses = True
                print("scanning is startes using tharding")

                therad1 = threading.Thread(target=prosseofScan,
                                           args=(repo_type, name, request, git_url, git_username, access_tocken))

                therad1.start()
                therad1.join()
                return redirect('repo_report')
            except Exception as e:
                print(e)
                print('repo is not scanning')
        else:
            print("git config data is none")
    else:
        print('git config data was not pass in post method')

    return render(request, 'git-leaks-scan.html')


# ------------------------------ GIT SCANHISTORY ---------------------------------------

def git_scan_history(request):
    first_letter = get_profile_first_img(request)
    dir_path = os.path.join(settings.BASE_DIR, 'gitleaksoutput')
    user_git_report_fils = get_files_starting_with(dir_path, request.user.username + "-")
    file, file_time, file_dtae = get_file_creation_info(dir_path)
    print(file_time, file_dtae)
    modified_file_names = [file_name.replace(request.user.username + '-', '').replace('.json', '') for file_name in
                           user_git_report_fils]
    index = []
    for i in range(1, len(file) + 1):
        index.append(i)

    print("thisis inesx  ---", index)
    fillfileinfo = zip(modified_file_names, index, file_time, file_dtae)

    context = {
        'jsonfilenames': fillfileinfo,
        "first_letter":first_letter+".png",
    }

    if request.method == 'POST':
        selected_file = request.POST.get('filename')
        request.session['selected_file'] = request.user.username + '-' + selected_file + '.json'
        return redirect('git_dashboard')
    return render(request, 'git-scan-history.html', context=context)


# ------------------------------ GIT DASHBOARD ------------------------------------------

@login_required
def git_dashboard(request):
    first_letter = get_profile_first_img(request)
    dir_path = os.path.join(settings.BASE_DIR, 'gitleaksoutput')
    user_latest_file = get_latest_file_creation_time(dir_path)
    # print(user_latest_file)
    user_latest_json_file = find_latest_file_with_prefix(request.user.username, dir_path)
    print('----- latest file ------', user_latest_json_file)

    if request.session.get('selected_file') is None:
        request.session['selected_file'] = user_latest_json_file
    else:
        print('file was selected')

    print('selcted fiel is : ', request.session.get('selected_file'))

    file_path = os.path.join(settings.BASE_DIR, 'gitleaksoutput', request.session.get('selected_file'))
    print(f'---------------------- file path : {file_path} ----------------------------')
    with open(file_path) as f:
        data = json.load(f)

    # Extract only the Author field
    authors = [entry['Author'] for entry in data]

    # Print or process the list of authors
    print(authors)
    total_secret = len(data)

    keys_to_extract = ['Description', 'StartLine', 'EndLine', 'StartColumn', 'EndColumn', 'Match', 'Secret',
                       'File', 'Commit', 'Entropy', 'Author', 'Email', 'Date', 'Message', 'RuleID', 'Fingerprint']
    git_data_obj = [{key: item[key] for key in keys_to_extract} for item in data]
    filtered_git_data_list = git_data_obj

    author_counts = Counter(authors)
    unique_names = list(author_counts.keys())
    values_list = list(author_counts.values())
    two_d_array = [[key, value] for key, value in author_counts.items()]

    rule_id_counts = {}
    for item in data:
        rule_id = item["RuleID"]
        rule_id_counts[rule_id] = rule_id_counts.get(rule_id, 0) + 1

    # Print the results
    result_2d_array = [[rule_id, count] for rule_id, count in rule_id_counts.items()]
    print(result_2d_array)

    # print(author_counts)
    #     # print(unique_names)
    #     # print(values_list)
    #     # print(two_d_array)

    labels_gtl = [item[0] for item in result_2d_array]
    values_gtl = [item[1] for item in result_2d_array]

    # Create bar chart
    fig = go.Figure(data=[go.Bar(x=labels_gtl, y=values_gtl)])

    fig.update_layout(
        height=345,  # Set height to 400 pixels
        # plot_bgcolor='rgba(0,0,0,0)',  # Set plot background color to transparent
        # paper_bgcolor='rgba(0,0,0,0)'  # Set paper background color to transparent
    )

    # Convert the Plotly figure to HTML
    plotly_chart = fig.to_html(full_html=False)
    print(unique_names)
    context = {
        'dataofgitlik': filtered_git_data_list,
        'counter_data': author_counts,
        'unique_names': unique_names,
        'values_list': values_list,
        'two_d_array': two_d_array,
        'plotly_chart': plotly_chart,
        "first_letter":first_letter+".png",
    }
    return render(request, 'git-reposcanner-table.html', context=context)


# ------------------------------ GIT PDF REPORT --------------------------------------

def got_html_to_pdf(request):
    # dynamic json file
    dir_path = os.path.join(settings.BASE_DIR, 'gitleaksoutput')
    latest_file_info = get_latest_file_creation_time(dir_path)
    filename = request.session.get('selected_file')
    if filename is None:
        request.session['filepathofgit'] = latest_file_info
        file_path = os.path.join(settings.BASE_DIR, 'gitleaksoutput', latest_file_info)
        with open(file_path) as f:
            data = json.load(f)
    else:
        request.session['filepathofgit'] = filename
        file_path = os.path.join(settings.BASE_DIR, 'gitleaksoutput', filename)
        with open(file_path) as f:
            data = json.load(f)
    keys_to_extract = ['Description', 'StartLine', 'EndLine', 'StartColumn', 'EndColumn', 'Match', 'Secret',
                       'File', 'Commit', 'Entropy', 'Author', 'Email', 'Date', 'Message', 'RuleID', 'Fingerprint']
    git_data_obj = [{key: item[key] for key in keys_to_extract} for item in data]

    # Render HTML content using Django template
    html_string = render_to_string('git-report-pdf.html', {'data': git_data_obj})

    # Convert HTML to PDF using wkhtmltopdf
    command = [
        'wkhtmltopdf',
        '--quiet',
        '--margin-top', '0',
        '--margin-bottom', '0',
        '--margin-left', '0',
        '--margin-right', '0',
        '-', '-'
    ]
    pdf_file = subprocess.run(command, input=html_string.encode('utf-8'), stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE)

    # Return PDF as response
    response = HttpResponse(pdf_file.stdout, content_type='application/pdf')
    response['Content-Disposition'] = f'inline; filename="{filename}.pdf"'
    return response

# from django.http import HttpResponse
# from django.template.loader import render_to_string
# from weasyprint import HTML
#
#
# def got_html_to_pdf(request):
#     # Generate HTML content using a Django template
#     context = {'title': 'My PDF Report', 'content': 'This is the content of my PDF report.'}
#     html_content = render_to_string('pdf_template.html', context)
#
#     # Convert HTML content to PDF using WeasyPrint
#     pdf_file = HTML(string=html_content).write_pdf()
#
#     # Create HTTP response with PDF file
#     response = HttpResponse(pdf_file, content_type='application/pdf')
#     response['Content-Disposition'] = 'filename="my_report.pdf"'
#     return response

# def html_to_pdf(request):
#     # dynamic json file
#     folder_path = os.path.join(settings.BASE_DIR, 'output/prowler-output-891377055878-20240215180534.json')
#     with open(folder_path) as f:
#         print()
#         data = json.load(f)
#     keys_to_extract = ['ServiceName', 'Status', 'Severity', 'ResourceType', 'ResourceDetails', 'Region', 'CheckTitle',
#                        'RelatedUrl']
#     data_obj = [{key: item[key] for key in keys_to_extract} for item in data]
#
#     # Render HTML content using Django template
#
#     html_string = render_to_string('pdf-templet.html', {'data': data_obj})
#
#     # # Convert HTML to PDF using wkhtmltopdf
#     pdf_file = subprocess.run(['wkhtmltopdf', '--quiet', '-', '-'], input=html_string.encode('utf-8'),
#                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
#
#     # Return PDF as response
#     response = HttpResponse(pdf_file.stdout, content_type='application/pdf')
#     response['Content-Disposition'] = 'attachment; filename="output.pdf"'
#     return response


def html_to_pdf(request):
    # dynamic json file
    folder_path = os.path.join(settings.BASE_DIR, 'output/prowler-output-891377055878-20240215180534.json')
    with open(folder_path) as f:
        data = json.load(f)
    keys_to_extract = ['ServiceName', 'Status', 'Severity', 'ResourceType', 'ResourceDetails', 'Region', 'CheckTitle', 'RelatedUrl']
    data_obj = [{key: item[key] for key in keys_to_extract} for item in data]

    # Render HTML content using Django template
    html_string = render_to_string('pdf-templet.html', {'data': data_obj})

    # Convert HTML to PDF using wkhtmltopdf with custom options for page size and margins
    options = [
        '--quiet',
        '--page-size', 'A4',
        '--margin-top', '0mm',
        '--margin-bottom', '0mm',
        '--margin-left', '0mm',
        '--margin-right', '0mm',
        '-'
    ]
    pdf_file = subprocess.run(['wkhtmltopdf'] + options, input=html_string.encode('utf-8'),
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # Return PDF as response
    response = HttpResponse(pdf_file.stdout, content_type='application/pdf')
    response['Content-Disposition'] = 'attachment; filename="output.pdf"'
    return response



import git


def clone_repository(repo_url, clone_location):
    try:
        # Clone the repository
        repo = git.Repo.clone_from(repo_url, clone_location)
        print("Repository cloned successfully")
    except git.GitCommandError as e:
        print("Error:", e)


# Example usage:
repository_url = 'https://github.com/zpqrtbnk/test-repo.git'
clone_location = 'name/002'


def get_repository_name_from_url(url):
    # Regular expression to extract the repository name from the URL
    pattern = r"github\.com/[^/]+/([^/]+)\.git"

    # Attempt to match the pattern in the URL
    match = re.search(pattern, url)

    if match:
        repository_name = match.group(1)  # Extract the repository name
        repository_name = repository_name.replace(".", "-")  # Remove periods from the repository name
        return repository_name
    else:
        return None


def clone_private_repo(repo_url, username, access_token, destination):
    try:
        # Formulate the Git clone command
        clone_command = ["git", "clone", repo_url, destination]

        # If both username and access token are provided, add them to the URL
        if username and access_token:
            repo_url_with_auth = f"https://{username}:{access_token}@{repo_url.split('https://')[1]}"
            clone_command[2] = repo_url_with_auth

        # Execute the Git clone command
        subprocess.check_call(clone_command)
        print("Repository cloned successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error cloning repository: {e}")


def scan_repository_with_gitleaks(repo_url, output_file):
    try:
        # Run GitLeaks as a subprocess to scan the repository
        result = subprocess.run(['gitleaks', '--url', repo_url], capture_output=True, text=True)

        # Print the output for debugging
        print("GitLeaks output:", result.stdout)

        # Write the output to a JSON file
        with open(output_file, 'w') as f:
            f.write(json.dumps(result.stdout))

        print(f"Scan result saved to {output_file}")
    except FileNotFoundError:
        print("GitLeaks not found. Please make sure it's installed and accessible in your system.")
    except Exception as e:
        print("An error occurred:", e)


def run_gitleaks_command(source_path, report_path):
    try:
        # Run gitleaks detect command to scan the repository and output the results in JSON format
        subprocess.run(['gitleaks', 'detect', '-s', source_path, '-r', report_path])
        print(f"Gitleaks scan completed successfully. Results written to {report_path}")
    except Exception as e:
        print("Error:", e)


def remove_directory(directory_path):
    try:
        # Attempt to remove the directory and its contents
        os.system(f'rmdir /s /q "{directory_path}"')
        print(f"Directory '{directory_path}' and its contents successfully removed.")
    except Exception as e:
        print(f"Error: {e}")


def get_current_date_and_time():
    # Get current date and time
    current_datetime = datetime.now()
    return current_datetime


def prosseofScan(repo_type, name, request, git_url, git_username, access_tocken=''):
    if repo_type == "public":
        clone_repository(repository_url, f'reposatoty/{name}')
        print('repo is coned')
        run_gitleaks_command(f'reposatoty/{name}', f'gitleaksoutput/{request.user.username}-{name}.json')
        remove_directory(f'reposatoty/{name}')
        request.session['git_report_file_name'] = f'{request.user.username}-{name}.json'

    elif repo_type == "private":
        clone_private_repo(git_url, git_username, access_tocken, f'reposatoty/{name}')
        run_gitleaks_command(f'reposatoty/{name}', f'gitleaksoutput/{request.user.username}-{name}.json')
        remove_directory(f'reposatoty/{name}')
        request.session['git_report_file_name'] = f'{request.user.username}-{name}.json'

    else:
        print("note validate")

    # ------------------- GET LETE USER FILES --------------------------


def get_files_starting_with(directory, prefix):
    try:
        # Get a list of all files in the directory
        file_names = os.listdir(directory)
        # Filter file names that start with the prefix
        filtered_files = [file_name for file_name in file_names if file_name.startswith(prefix)]
        return filtered_files
    except Exception as e:
        print(f"Error accessing directory: {e}")
        return []


# ----------------------- GET LATEST FILE -------------------------------

def get_latest_file_creation_time(directory):
    """
    Get the creation time of the latest file in the given directory.

    Args:
        directory (str): The path to the directory.

    Returns:
        tuple: A tuple containing the name of the latest file and its creation time
               in a readable format (or None if no files are found).
    """
    # Get a list of all files in the directory
    files = os.listdir(directory)

    latest_creation_time = 0
    latest_file = None

    # Loop through each file and get its creation time
    for file in files:
        file_path = os.path.join(directory, file)
        if os.path.isfile(file_path):  # Check if it's a file and not a directory
            creation_time = os.path.getctime(file_path)
            if creation_time > latest_creation_time:
                latest_creation_time = creation_time
                latest_file = file

    if latest_file:
        latest_file_path = os.path.join(directory, latest_file)
        latest_creation_time_readable = time.ctime(latest_creation_time)
        return latest_file
    else:
        return None


# ---------------------------------- FILE CREATION TIME ----------------------

def get_file_creation_info(directory):
    file_paths = []
    file_times = []
    file_dates = []

    for root, dirs, files in os.walk(directory):
        for file in files:
            filepath = os.path.join(root, file)
            creation_time = os.path.getctime(filepath)
            formatted_time = datetime.fromtimestamp(creation_time).strftime('%H:%M')
            formatted_date = datetime.fromtimestamp(creation_time).strftime('%d/%m/%Y')
            file_paths.append(filepath)
            file_times.append(formatted_time)
            file_dates.append(formatted_date)

    return file_paths, file_times, file_dates


def find_latest_file_with_prefix(prefix, directory="."):
    latest_file = None
    latest_time = 0
    for root, dirs, files in os.walk(directory):
        for file in files:
            if prefix in file:
                file_path = os.path.join(root, file)
                file_time = os.path.getmtime(file_path)
                if file_time > latest_time:
                    latest_time = file_time
                    latest_file = file
    return latest_file
