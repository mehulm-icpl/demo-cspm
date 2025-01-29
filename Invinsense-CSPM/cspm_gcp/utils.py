import pandas as pd  # Used to handle dataframes
import plotly.express as px

def gcp_doghnut_chart(data):
    danger_count = data['danger']
    warning_count = data['warning']
    good_count = data['good']
    
    result_list = [danger_count, warning_count, good_count]
    return result_list

def gcp_azure_severity(data):
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
