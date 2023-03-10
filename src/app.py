import dash_bootstrap_components as dbc
from dash import html, Dash, dcc
import datetime
from PIL import Image
from dash.dependencies import Input, Output
import pandas as pd 
import dash
import openpyxl
import pandas as pd
import plotly
from dash.exceptions import PreventUpdate
from dash.dependencies import Input, Output
import plotly.express as px
import dash_bootstrap_components as dbc
from dash import html, Dash, dcc, ctx
from email.message import EmailMessage  # for sending emails
import smtplib                          # for sending emails
import re
from plotly.subplots import make_subplots




app = Dash(__name__, external_stylesheets=[dbc.themes.DARKLY, dbc.icons.BOOTSTRAP, dbc.icons.FONT_AWESOME],suppress_callback_exceptions=True)
server = app.server

# fig = make_subplots(rows=1,cols=3)
app.layout = html.Div([
	dcc.Location(id='url', refresh=False),
	html.Div(id='page-content'),
	dcc.Store(id='index_input',storage_type='session'),
])

alert = dbc.Alert("To get all CVE info subscribe to email alert!", color="danger",dismissable=True)

pil_img = Image.open("../data/csw.png")
df_ransomware = pd.read_csv("../data/strategic.csv")
ransomware_families = df_ransomware['Ransomware Family'].to_list()
df_tactics = pd.read_csv("../data/tactical.csv")
malware_families_tactics = df_tactics['Malware Family'].to_list()
df_vuln = pd.read_csv("../data/ransomwarecves.csv")
# malware_families_vuln = df_vuln['Operator Name'].unique().tolist()
# operator_cve_mapping = {}
# for operator in malware_families_vuln:
# 	df_vuln_op = df_vuln[df_vuln['Operator Name']==operator].reset_index()
# 	comma_seperated_op_cve = df_vuln_op['CVE'].to_list()
# 	op_cve = []
# 	for cve_str in comma_seperated_op_cve:
# 		cve_str_list = cve_str.split(',')
# 		op_cve.extend(cve_str_list)
# 	operator_cve_mapping[operator] = ",".join(list(set(op_cve)))
    
df_hacks = pd.read_csv('../data/hacks-of-the-day - hacks-of-the-day.csv',encoding='cp1252')
# trending_family_name = df_hacks['Attacker name'].value_counts().keys().tolist()
# trending_family_name = trending_family_name[:5]
trending_family_name = ['LockBit3.0','BlackCat','Royal','Vice Society','Play']
df_aug = pd.read_csv('../data/August.csv', encoding = "ISO-8859-1")
df_sep = pd.read_csv('../data/Sep.csv', encoding = "ISO-8859-1")
df_oct = pd.read_csv('../data/oct.csv', encoding = "ISO-8859-1")
df_nov = pd.read_csv('../data/nov.csv', encoding = "ISO-8859-1")
df_dec = pd.read_csv('../data/dec.csv', encoding = "ISO-8859-1")
df_jan = pd.read_csv('../data/jan.csv',encoding='ISO-8859-1')
df_feb = pd.read_csv('../data/feb.csv',encoding='ISO-8859-1')
df_attack_vector = pd.read_csv('../data/attack vector.csv',encoding='cp1252')
sector_unique_family = []
newWorkbook = openpyxl.load_workbook('../data/5 month data.xlsx')
for sheet in newWorkbook.sheetnames:
	df_sector = pd.read_excel('../data/5 month data.xlsx',sheet_name=sheet)
	sector_unique_family.extend(df_sector['Operator'].unique().tolist())
sector_unique_family = list(set(sector_unique_family))


dff_funnel = pd.read_csv("../data/funnelchart - Sheet1.csv")
ransomware_ioc_count = {}
ransomware_ioc_count_dict = {'Ransomware Family': [], 'IOC Count': []}
for i in range(dff_funnel.shape[0]):
    if dff_funnel.loc[i,'Ransomware Family'] not in ransomware_ioc_count:
        ransomware_ioc_count[dff_funnel.loc[i,'Ransomware Family']] = dff_funnel.loc[i,'IOC Count']
    else:
        ransomware_ioc_count[dff_funnel.loc[i,'Ransomware Family']] = ransomware_ioc_count[dff_funnel.loc[i,'Ransomware Family']] + dff_funnel.loc[i,'IOC Count']
# print(ransomware_ioc_count)
for key, item in ransomware_ioc_count.items():
    ransomware_ioc_count_dict['Ransomware Family'].append(key)
    ransomware_ioc_count_dict['IOC Count'].append(item)
# print(ransomware_ioc_count_dict)
dff_new = pd.DataFrame.from_dict(ransomware_ioc_count_dict)
dff_new = dff_new.sort_values(by=['IOC Count'], ascending=False)
dff_new = dff_new.head(5).reset_index(drop=True)
# print(dff_new)
top5_families = dff_new['Ransomware Family'].tolist()
# print(top5_families)
dff_new_top5 = dff_funnel[dff_funnel['Ransomware Family'].isin(top5_families)].reset_index(drop=True)
# print(dff_new_top5)
df_final = pd.DataFrame()
for fam in top5_families:
    df_strip = dff_new_top5[dff_new_top5['Ransomware Family']==fam].reset_index(drop=True)
    frames = [df_final,df_strip]
    df_final = pd.concat(frames,axis=0)
#print(df_final)



interval = 6000
emailsendingransomware=[]
with open('ransomwareemailsent.txt','r') as f:
        ransomwaretosend=[i for i in f.read().split('\n')]
df1=pd.read_csv('newgroup.csv')
df=pd.read_csv('ransomware.csv')
df=df[df.duplicated(subset=['Ransomware'], keep=False)]
uniquehostname=df['Ransomware'].unique()
cards=['N/A','N/A','N/A','N/A','N/A']


tabs_styles = {
    'height': '35px'
}
tab_style = {
    'borderBottom': '1px solid #d6d6d6',
    'padding': '6px',
    'fontWeight': 'bold'
}
# #000000
tab_selected_style = {
    'borderTop': '1px solid #d6d6d6',
    'borderBottom': '1px solid #d6d6d6',
    'backgroundColor': 'black',
    'color': 'white',
    'fontWeight': 'bold',
    'padding': '6px'
}


month_dict = {
    1: 'August',
	2: 'September',
	3: 'October',
	4: 'November',
	5: 'December',
	6: 'January',
    7: 'February'
}

sector_month_dict = {
	1: 'August',
	2: 'September',
	3: 'October',
	4: 'November',
	5: 'December'
}



##callback for strategic intelligence
@app.callback(
    Output('the_card_strategic_1', 'children'),
    [Input('my_dropdown_2','value')]
)


def update_card_strategic_1(my_dropdown_2):
	dff = df_ransomware
	df_selected = dff[dff['Ransomware Family'] == my_dropdown_2].reset_index()   
	card1 = dbc.Card(
		dbc.CardBody(
			[
				html.Div([
			html.H5(f"Data Exposure", className="text-nowrap text-warning fw-bold",style={'textAlign':'center'}),       
			html.H6(f"{df_selected.loc[0,'Data Exposure']}", className="text-nowrap fw-bold",style={'textAlign':'center'}),
		]),
		], class_name="border-start border-warning border-5 card border-primary mb-0 max-width: 60rem;"
		), class_name="text-left m-4",
	)
	card2 = dbc.Card(
		dbc.CardBody(
			[
				html.Div([
			html.H5(f"Denial", className="text-nowrap text-warning fw-bold",style={'textAlign':'center'}),
			html.H6(f"{df_selected.loc[0,'Denial']}", className="text-nowrap fw-bold",style={'textAlign':'center'}),
		]),
		], class_name="border-start border-warning border-5 card border-primary mb-0 max-width: 60rem;"
		), class_name=" text-left m-4",
	)
	card3 = dbc.Card(
		dbc.CardBody(
			[
				html.Div([
			html.H5(f"Modify", className="text-nowrap text-warning fw-bold",style={'textAlign':'center'}),        
			html.H6(f"{df_selected.loc[0,'Modify']}", className="text-nowrap fw-bold",style={'textAlign':'center'}),
		]),
		], class_name="border-start border-warning border-5 card border-primary mb-0 max-width: 60rem;"
		), class_name=" text-left m-4",
	)
	card4 = dbc.Card(
		dbc.CardBody(
			[
				html.Div([
			html.H5(f"Multiple Extortion", className="text-nowrap text-warning fw-bold",style={'textAlign':'center'}),
			html.H6(f"{df_selected.loc[0,'Multiple Extortion']}", className="text-nowrap fw-bold",style={'textAlign':'center'}),
		]),
		], class_name="border-start border-warning border-5 card border-primary mb-0 max-width: 60rem;"
		), class_name=" text-left m-4",
	)
	card5 = dbc.Card(
		dbc.CardBody(
			[
				html.Div([
			html.H5(f"Max $", className="text-nowrap text-warning fw-bold",style={'textAlign':'center'}),
			html.H6(f"{df_selected.loc[0,'Max $']}", className="text-nowrap fw-bold",style={'textAlign':'center'}),
		]),
		], class_name="border-start border-warning border-5 card border-primary mb-0 max-width: 60rem;"
		), class_name=" text-left m-4",
	)
	card6 = dbc.Card(
		dbc.CardBody(
			[
				html.Div([
			html.H5(f"Min $ ", className="text-nowrap text-warning fw-bold",style={'textAlign':'center'}),
			html.H6(f"{df_selected.loc[0,'Min $']}", className="text-nowrap fw-bold",style={'textAlign':'center'}),
		]),
		], class_name="border-start border-warning border-5 card border-primary mb-0 max-width: 60rem;"
		), class_name=" text-left m-4",
	)
	card7 = dbc.Card(
		dbc.CardBody(
			[
				html.Div([
			html.H5(f"Sensitive Data", className="text-nowrap text-warning fw-bold",style={'textAlign':'center'}),
			html.H6(f"{df_selected.loc[0,'Sensitive Data']}", className="text-nowrap fw-bold",style={'textAlign':'center'}),
		]),
		], class_name="border-start border-warning border-5 card border-primary mb-0 max-width: 60rem;"
		), class_name=" text-left m-4",
	)
	card8 = dbc.Card(
		dbc.CardBody(
			[
				html.Div([
			html.H5(f"Customer Data", className="text-nowrap text-warning fw-bold",style={'textAlign':'center'}),
			html.H6(f"{df_selected.loc[0,'Customer Data']}", className="text-nowrap fw-bold",style={'textAlign':'center'}),
		]),
		], class_name="border-start border-warning border-5 card border-primary mb-0 max-width: 60rem;"
		), class_name=" text-left m-4",
	)

	cards = dbc.Container([
		dbc.Row(
			[
				dbc.Col(card1, width=3),
				dbc.Col(card2, width=3),
				dbc.Col(card3, width=3),
				dbc.Col(card4, width=3),
			]
		),
		dbc.Row(
			[
				dbc.Col(card5, width=3),
				dbc.Col(card6, width=3),
				dbc.Col(card7, width=3),
				dbc.Col(card8, width=3),
			]
		),
	])                
	return cards




##callback for tactical intelligence
@app.callback(
    Output(component_id='the_card_tactic', component_property='children'),
    [Input(component_id='my_dropdown_2',component_property='value')]
)


def update_card_tactic(my_dropdown_2):
	print(my_dropdown_2)
	dff = df_tactics
	df_selected = dff[dff['Malware Family'] == my_dropdown_2].reset_index()
	tactic_list = str(df_selected.loc[0,'Tactics']).split(',')
	tactic_list = [x.strip() for x in tactic_list]
	group_item_list = []
	for tactic in tactic_list:
		group_item_list.append(dbc.ListGroupItem(str(tactic)))
	card1 = dbc.Card(
		dbc.ListGroup(
			group_item_list,
			flush=True,
		), class_name="text-left m-4",
	)
	return card1





##callback for vuln intelligence
@app.callback(
    [Output('the_card_vuln','children'),Output('the_card_vuln','value')],
    [Input('my_dropdown_2','value')]
)


def update_vuln(my_dropdown_vuln):
	dff = df_vuln
	# df_selected = dff[dff['Malware Family'] == my_dropdown_vuln].reset_index()
	# vuln_list = str(df_selected.loc[0,'CVE']).split(',')
	df_vuln_op = df_vuln[df_vuln['Operator Name']==my_dropdown_vuln].reset_index()
	comma_seperated_op_cve = df_vuln_op['CVE'].to_list()
	vuln_list = []
	for cve_str in comma_seperated_op_cve:
		cve_str_list = cve_str.split(',')
		vuln_list.extend(cve_str_list)
	vuln_list = list(set(vuln_list))
	vuln_list = [x.strip() for x in vuln_list]
	table_cve_list = []
	# alerts = dbc.Alert("This is a primary alert", color="primary")
	table_header = []
	table_body = []
	for cve in vuln_list:
		table_cve_list.append(html.Tr([html.Td(str(cve))]))
	print(len(table_cve_list))
	if len(table_cve_list)<=4:
		# print('Here1',my_dropdown_vuln)
		table_header = [
			html.Thead(html.Tr([html.Th("Associated CVEs")],className="text-warning fw-bold",style={'color':'black'}))
		]
		table_body = [html.Tbody(table_cve_list)]
		table = dbc.Table(table_header + table_body, bordered=True,dark=True,
		hover=True,
		responsive=True,
		striped=True,)  
	else:
		# print('Here2',my_dropdown_vuln)
		table_header = [
			html.Thead(html.Tr([html.Th("Associated CVEs")],className="text-warning fw-bold",style={'color':'black'}))
		]
		# table_cve_list = table_cve_list[:4]
		# table_cve_list.append(html.Tr([html.Td(str("To get all CVE info subscribe to email alert"))],className="text-primary fw-bold"))
		table_body = [html.Tbody(table_cve_list[:4])]
		# table_body.extend(html.Tbody('Alert!'))
		table = dbc.Table(table_header + table_body, bordered=True,dark=True,
		hover=True,
		responsive=True,
		striped=True,)  

		

	return table, len(table_cve_list)




##callback for alert
@app.callback(
    Output('the_alert','children'),
    [Input('the_card_vuln','value')]
)

def get_alert(table_cve_list):
    print(table_cve_list)
    alerts = ['']
    if table_cve_list>4:
        alerts = alert
    return alerts



#callback for recursive
@app.callback(
   Output('my_dropdown_2','value'),
   [Input('my_dropdown_2','value')] 
)

def select_family(my_dropdown_2):
    return my_dropdown_2


#callback for slider component
@app.callback(
    Output('our_graph','figure'),
    [Input('my_dropdown_2','value'),Input('my_range_slider','value')]
)


def build_graph(my_dropdown_2,my_range_slider):
    #print("Here",my_range_slider)
	dataframe_month = {
		'August': df_aug,
		'September': df_sep,
		'October': df_oct,
		'November': df_nov,
        'December': df_dec,
		'January': df_jan,
        'February': df_feb
	}
	month_list = []
	for num in range(my_range_slider[0],my_range_slider[1]+1):
		month_list.append(month_dict[num])
                
	industry_count_per_month = {'Months' : [], 'No of Extortion' : []}
	for month in month_list:
		dff = dataframe_month[month]
		industry_count_per_month['Months'].append(month)
		df_filter = dff[dff['Group']==my_dropdown_2]
		industry_count_per_month['No of Extortion'].append(df_filter.shape[0])
		
	df_new = pd.DataFrame.from_dict(industry_count_per_month)
	#print(df_test)
	fig = px.bar(df_new, x='Months', y='No of Extortion', color_discrete_sequence=["#ffc107"],template = "plotly_dark")

	fig.update_layout(yaxis={'title':'No of Extortion'},
						title={'text':'7-MONTHS TIMELINE','font':{'size':28},'x':0.5,'xanchor':'center'})



	fig.update_traces(width=0.2)
	return fig




def send_alert(subject, body, to):
    msg = EmailMessage()
    msg.set_content(body)
    msg['subject'] = subject
    msg['to'] = to
    print(subject)
    print(body)
    print(to)
    user = 'ransomwareport@gmail.com'      # <-- Update here-------------------
    msg['from'] = user
    password = 'brmyaejvhswmlsfu'      # <-- Update here-------------------

    # set server parameters
    server = smtplib.SMTP('smtp.gmail.com', 587) # create server variable
    server.starttls()
    server.login(user,password)
    server.send_message(msg)

    server.quit()

if len(df['Ransomware'])>0:
    if len(uniquehostname)>0:
        for i in range(len(uniquehostname)):
            cards[i]=uniquehostname[i]
            if uniquehostname[i] not in ransomwaretosend:
                emailsendingransomware.append(uniquehostname[i])
                ransomwaretosend.append(uniquehostname[i])
            if i==4:
                break

newgroup=['N/A','N/A','N/A','N/A','N/A','N/A']
uniquegroup=df1['Ransomware'].unique()
if len(uniquegroup)>0:
    for i in range(len(uniquegroup)):
        newgroup[i]=uniquegroup[i]
        if i==4:
            break


interval = dcc.Interval(interval=interval)

def checkemail(email):
    regex = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b"
    if(re.fullmatch(regex, email)):
        return True
    else:
        return False

@app.callback([Output("example-output", "children"),
Output('input','placeholder'),
Output('input','className'),
Output('example-button','className'),
Output('addtional-text','className'),
Output('additional-info','className'),
Output('additional-input','className'),
Output('additonal-button','className'),
Output('additional-output','children')],
[Input("alert-permission","value"),
Input('input','className'),
Input("input","value"),
Input("example-button", "n_clicks"),Input('additional-info','value'),Input('additonal-button','n_clicks'),Input("additional-input",'value')])

def on_button_click(alert_permission,classinfo,email,click,additonalradio,additionalclick,additionalemail):
    print(alert_permission)
    print(classinfo)
    print(email)
    print(click)
    print(additonalradio)
    print(additionalclick)
    print(additionalemail)
    if alert_permission=='No':
        return '','','invisible','invisible','invisible','invisible','invisible','invisible',''
    if alert_permission=='Yes, email alerts' and additonalradio=='No':
        if classinfo=='visible w-75':
            if click==0:
                return "Not clicked.",'Please enter your email id here','visible w-75','visible mt-4 bg-light border border-dark','visible mt-4 mb-2','visible','invisible','invisible',''
            elif click>0 and ctx.triggered_id=='example-button':
                if email!='' and email!=None:
                    print(email)
                    print('it came here')
                    isemail=checkemail(email)
                    if isemail==True:
                        send_alert('Alert: Trending Ransomware',
                                    f'Found Trending ransomware families, They are:\n {",".join([i for i in cards if i!="N/A"])}\n New groups are:\n {",".join(i for i in newgroup if i!="N/A")} ',
                                    email)
                        return f"Email Sent successfully",'Please enter your email id here','visible w-75','visible mt-4 bg-light border border-dark','visible mt-3 mb-2','visible','invisible','invisible',''
                    else:
                        return f"Invalid Email id, please enter correct email",'Please enter your email id here','visible w-75','visible mt-4 bg-light border border-dark','visible mt-3 mb-2','visible','invisible','invisible',''
        else:
            return '','Please enter your email id here','visible w-75','visible mt-4 bg-light border border-dark','visible mt-3 mb-2','visible','invisible','invisible',''
    elif alert_permission=='Yes, email alerts' and additonalradio=='Yes, email alerts':
            if click==0 and additionalclick==0:
                return "Not clicked.",'Please enter your email id here','visible w-75','visible mt-4 bg-light border border-dark','visible mt-4','visible','visible w-75','visible mt-3 bg-light border border-dark','Not clicked'
            elif click!=0 and ctx.triggered_id=='example-button':
                if email!='' or email!=None:
                    isemail=checkemail(email)
                    if isemail==True:
                        send_alert('Alert: Trending Ransomware',
                                    f'Found Trending ransomware families, They are:\n {",".join([i for i in cards if i!="N/A"])}\n New groups are:\n {",".join(i for i in newgroup if i!="N/A")} ',
                                    email)
                        return f"Email Sent successfully",'Please enter your email id here','visible w-75','visible mt-4 bg-light border border-dark','visible mt-4 mb-2','visible','visible w-75','visible mt-3 bg-light border border-dark',''
                    else:
                        return f"Invalid Email id, please enter correct email",'Please enter your email id here','visible w-75','visible mt-4 bg-light border border-dark','visible mt-4 mb-2','visible','visible w-75','visible mt-3 bg-light border border-dark',''
            elif additionalclick!=0 and ctx.triggered_id=='additonal-button':
                if additionalemail!='' or additionalemail!=None:
                    isemail=checkemail(additionalemail)
                    if isemail==True:
                        send_alert('New user subscription',f'New user would like to subscribe {additionalemail}',
                                    'thahasinam@gmail.com')
                        return f"",'Please enter your email id here','visible w-75','visible mt-4 bg-light border border-dark','visible mt-4 mb-2','visible','visible w-75','visible mt-3 bg-light border border-dark','Thank you, you will be added to the list of subscribers'
                    else:
                        return f"",'Please enter your email id here','visible w-75','visible mt-4 bg-light border border-dark','visible mt-4 mb-2','visible','visible w-75','visible mt-3 bg-light border border-dark','Invalid Email id, please enter correct email'
            else:
                return "Not clicked.",'Please enter your email id here','visible w-75','visible mt-4 bg-light border border-dark','visible mt-4','visible','visible w-75    ','visible mt-3 bg-light border border-dark','Not clicked'



# callback for intent and capability
@app.callback(
    Output('the_card_intent','children'),
    [Input('my_dropdown_2','value')])


def update_card_intent(my_dropdown_2):
	dff = df_hacks
	target_pattern = ['hospital','manufactur','law','public sector']
	dff_target = dff[dff['Attacker name']==my_dropdown_2].reset_index()
	dff_target['Exfiltrated data amount'] = dff_target['Exfiltrated data amount'].astype('str')
	category_list = dff_target['Category'].unique().tolist()
	# dff_target['Exfiltrated data amount'].replace(' GB','',inplace=True)
	data_extortion = list(set(dff_target['Exfiltrated data amount'].unique().tolist()))
	if 'N/A' in data_extortion:
		data_extortion.remove('N/A')
	if 'nan' in data_extortion:
		data_extortion.remove('nan')
	size_classification = {'TB':[],'GB':[],'Other':[]}
	for i in range(len(data_extortion)):
		data_extortion[i] = str(data_extortion[i]).lower()
		if ' gb' in data_extortion[i] or ' tb' in data_extortion[i]:
			data_extortion[i] = data_extortion[i].replace(',','.')
		if ' gb' in data_extortion[i]:
			data_extortion_split_gb = str(data_extortion[i]).split(' gb')
			for val in data_extortion_split_gb:
				if val.isnumeric() == True:
					data_size_num_gb = int(val)
					size_classification['GB'].append(data_size_num_gb)
					break
			
		elif ' tb' in data_extortion[i]:
			data_extortion_split_tb = str(data_extortion[i]).split(' tb')
			for val in data_extortion_split_tb:
				if val.isnumeric() == True:
					data_size_num_tb = int(val)
					size_classification['TB'].append(data_size_num_tb)
					break
		else:
			data_size_other = str(data_extortion[i]).split(' ')
			for val in data_size_other:
				val = val.replace(',','')
				if val.isnumeric() == True:
					size_classification['Other'].append(int(val))
        
	print(size_classification)
        
	# for val in data_extortion:
	# 	val = str(val).lower()
	# 	if ' gb' in val or ' tb' in val:
	# 		if ',' in val:
	# 			val = val.replace(',','.')
	# 			print(val)
                                
	# print(category_list)
	# print(dff_target['Exfiltrated data amount'])
	# print(data_extortion)
            
	target = "NO"
	opportunistic = "NO"
	hybrid = "NO"
	data_extortion = "N/A"
	if len(size_classification['TB']) > 0:
		data_extortion = f"{size_classification['TB'][0]} TB"
	elif len(size_classification['GB']) > 0:
		data_extortion = f"{size_classification['GB'][0]} GB"
	elif len(size_classification['Other']) > 0:
		data_extortion = f"{size_classification['Other'][0]} files"
    
	
	size_classification['TB'].sort(reverse=True)
	size_classification['GB'].sort(reverse=True)
	size_classification['Other'].sort(reverse=True)

	for val in category_list:
		for pattern in target_pattern:
			if pattern in val:
				target = "YES"
			else:
				opportunistic = "YES"
		if (target == "YES") and (opportunistic == "YES"):
			hybrid = "YES"
			break
    
	
	
            
    
	card1 = dbc.Card(
			dbc.CardBody(
				[
					html.Div([
				html.H5(f"Opportunistic", className="text-nowrap text-warning fw-bold",style={'textAlign':'center'}),       
				html.H6(f"{opportunistic}", className="text-nowrap fw-bold",style={'textAlign':'center'}),
			]),
			], class_name="border-start border-warning border-5 card border-primary mb-0 max-width: 60rem;"
			), class_name="text-left m-4",
		)   
	card2 = dbc.Card(
			dbc.CardBody(
				[
					html.Div([
				html.H5(f"Target", className="text-nowrap text-warning fw-bold",style={'textAlign':'center'}),       
				html.H6(f"{target}", className="text-nowrap fw-bold",style={'textAlign':'center'}),
			]),
			], class_name="border-start border-warning border-5 card border-primary mb-0 max-width: 60rem;"
			), class_name="text-left m-4",
		)  
	card3 = dbc.Card(
			dbc.CardBody(
				[
					html.Div([
				html.H5(f"Hybrid", className="text-nowrap text-warning fw-bold",style={'textAlign':'center'}),       
				html.H6(f"{hybrid}", className="text-nowrap fw-bold",style={'textAlign':'center'}),
			]),
			], class_name="border-start border-warning border-5 card border-primary mb-0 max-width: 60rem;"
			), class_name="text-left m-4"
		)  
	card4 = dbc.Card(
			dbc.CardBody(
				[
					html.Div([
				html.H5(f"Exfiltration (Max)", className="text-nowrap text-warning fw-bold",style={'textAlign':'center'}),       
				html.H6(f"{data_extortion}", className="text-nowrap fw-bold",style={'textAlign':'center'}),
			]),
			], class_name="border-start border-warning border-5 card border-primary mb-0 max-width: 60rem;"
			), class_name="text-left m-4"
		)      

	cards = dbc.Container([
			dbc.Row(
				[
					dbc.Col(card1, width=3),
					dbc.Col(card2, width=3),
					dbc.Col(card3, width=3),
					dbc.Col(card4, width=3),
				]
			),
		])
	return cards


# callback for piechart
@app.callback(
	Output('the_piechart_graph','figure'),
    [Input('my_dropdown_2','value')]
)

def update_piechart_graph(my_dropdown_2):
	dff = df_hacks
	ransomware_sector_mapping = {}
	for trending in trending_family_name:
		dff_test = dff[dff['Attacker name']==trending].reset_index(drop=True)
		category_list = dff_test['Generalize'].value_counts().keys().tolist()
		# category_list = dff_test['Generalize'].value_counts().to_frame('counts').reset_index()
		print(category_list)
		if len(category_list) > 7:
			category_list = category_list[:7]
		dff_test = dff_test[dff_test['Generalize'].isin(category_list)].reset_index(drop=True)
		
		ransomware_sector_mapping[trending] = dff_test['Generalize'].tolist()

	
	# print(dff_test_strip)
	# ransomware_sector_mapping[my_dropdown_2] = category_list

	# print(ransomware_sector_mapping)
	dff_selected = pd.DataFrame(dict([ (k,pd.Series(v)) for k,v in ransomware_sector_mapping.items() ]))
	# if category_list.shape[0] > 7:
	# 	dff_selected = category_list.head(7)
	# else:
	# 	dff_selected = category_list
	
	piechart = px.pie(
		data_frame = dff_selected,
		names = my_dropdown_2,
		hole = .4,
		color_discrete_sequence=["#5cb85c", "#5bc0de", "#ffc107"],
		#color="smoker",
		template = "plotly_dark",
	)
	return(piechart)	




# callback for donut
@app.callback(
	Output('the_attack_vector','children'),
    [Input('my_dropdown_2','value')]
)


def update_attack_vector(my_dropdown_2):
	dff = df_attack_vector
	attack_vector_list = dff[my_dropdown_2].dropna().tolist()

	group_item_list = []
	for vector in attack_vector_list:
		group_item_list.append(dbc.ListGroupItem(str(vector)))
	
	card1 = dbc.Card(
		dbc.ListGroup(
			group_item_list,
			flush=True,
		), class_name="text-left m-4",
	)
	return card1

#callback for recursive sector
@app.callback(
   Output('my_dropdown_3','value'),
   [Input('my_dropdown_3','value')] 
)

def select_family(my_dropdown_3):
    return my_dropdown_3


#callback for slider component sector
@app.callback(
    Output('our_graph_sector','figure'),
    [Input('my_dropdown_3','value'),Input('my_range_slider_1','value')]
)


def build_graph(my_dropdown_2,my_range_slider):
    #print("Here",my_range_slider)
	dataframe_month = {
		'August': 'August',
		'September': 'September',
		'October': 'October',
		'November': 'Nov',
        'December': 'Dec'
	}
	month_list = []
	for num in range(my_range_slider[0],my_range_slider[1]+1):
		month_list.append(month_dict[num])
                
	# industry_count_per_month = {'Top 7 Sectors' : [], 'No of Attacks' : []}

	df_final = pd.DataFrame()
	ransomware_sector_mapping = {}
	for month in month_list:
		dff = pd.read_excel('5 month data.xlsx',sheet_name=dataframe_month[month])
		dff = dff[dff['Operator']==my_dropdown_2].reset_index(drop=True)
		frames = [df_final,dff]
		df_final = pd.concat(frames,ignore_index=True)
	category_list = df_final['General'].value_counts().keys().tolist()
	if len(category_list) > 7:
			category_list = category_list[:7]
	dff_test = df_final[df_final['General'].isin(category_list)].reset_index(drop=True)
	ransomware_sector_mapping[my_dropdown_2] = dff_test['General'].tolist()
	dff_selected = pd.DataFrame(dict([ (k,pd.Series(v)) for k,v in ransomware_sector_mapping.items() ]))

	piechart = px.pie(
		data_frame = dff_selected,
		names = my_dropdown_2,
		hole = .4,
		color_discrete_sequence=["#5cb85c", "#5bc0de", "#ffc107"],
		#color="smoker",
		template = "plotly_dark",
	)
	return(piechart)



def funnelchart():
    fig = px.funnel(df_final, y='Ransomware Family', x='IOC Count', color='IOC Type', template = "plotly_dark", 
    # labels={
    #   "Domain": "<b>Domain</b>","Ip": "<b>Ip</b>"}
      )
    # fig.append_trace(
    #     fig1,row=1,col=1
	# )
    
    # fig.update_traces(textposition='outside')
    # fig.update_layout(uniformtext_minsize=35)
    fig.update_traces(textfont = {'color': 'white'})
    fig.update_layout(height=400, width=400, funnelmode= "stack", legend=dict(
    orientation="h",
    #entrywidth=70,
    yanchor="bottom",
    y=1.02,
    xanchor="right",
    x=1,
    traceorder="reversed",
        #title_font_family="Times New Roman",
        font=dict(
            #family="Courier",
            size=12,
            color="white",
        ),
        bgcolor="black",
        bordercolor=" gold",
        borderwidth=2,
))
    return fig


def funnelchart2():
    fig = px.funnel(df_final, y='Ransomware Family', x='IOC Count', color='IOC Type', template = "plotly_dark")
    # fig.append_trace(
    #     fig2,row=1,col=2
	# )
    fig.update_traces(textfont = {'color': 'white'})
    fig.update_layout(height=400, width=400, legend=dict(
    orientation="h",
    #entrywidth=70,
    yanchor="bottom",
    y=1.02,
    xanchor="right",
    x=1,
    traceorder="reversed",
        #title_font_family="Times New Roman",
        font=dict(
            #family="Courier",
            size=12,
            color="white",
        ),
        bgcolor="black",
        bordercolor=" gold",
        borderwidth=2,
))
    return fig


def funnelchart3():
    
    fig = px.funnel(df_final, y='Ransomware Family', x='IOC Count', color='IOC Type', template = "plotly_dark")
    # fig.append_trace(
    #     fig3,row=1,col=3
	# )
    fig.update_traces(textfont = {'color': 'white'})
    fig.update_layout(height=400, width=400, legend=dict(
    orientation="h",
    #entrywidth=70,
    yanchor="bottom",
    y=1.02,
    xanchor="right",
    x=1,
    traceorder="reversed",
        #title_font_family="Times New Roman",
        font=dict(
            #family="Courier",
            size=12,
            color="white",
        ),
        bgcolor="black",
        bordercolor=" gold",
        borderwidth=2,
))
    return fig





card1 = dbc.Card(
	dbc.CardBody(
		[
			html.Div([
		html.H5(f"Trend #1", className="text-nowrap text-warning fw-bold",style={'textAlign':'center'}),       
		html.H6(f"{trending_family_name[0]}", className="text-nowrap fw-bold",style={'textAlign':'center'}),
	]),
	], class_name="border-start border-warning border-5 card border-primary mb-0 max-width: 60rem;"
	), class_name="text-left m-4",
)

card2 = dbc.Card(
	dbc.CardBody(
		[
			html.Div([
		html.H5(f"Trend #2", className="text-nowrap text-warning fw-bold",style={'textAlign':'center'}),       
		html.H6(f"{trending_family_name[1]}", className="text-nowrap fw-bold",style={'textAlign':'center'}),
	]),
	], class_name="border-start border-warning border-5 card border-primary mb-0 max-width: 60rem;"
	), class_name="text-left m-4",
)

card3 = dbc.Card(
	dbc.CardBody(
		[
			html.Div([
		html.H5(f"Trend #3", className="text-nowrap text-warning fw-bold",style={'textAlign':'center'}),       
		html.H6(f"{trending_family_name[2]}", className="text-nowrap fw-bold",style={'textAlign':'center'}),
	]),
	], class_name="border-start border-warning border-5 card border-primary mb-0 max-width: 60rem;"
	), class_name="text-left m-4",
)

card4 = dbc.Card(
	dbc.CardBody(
		[
			html.Div([
		html.H5(f"Trend #4", className="text-nowrap text-warning fw-bold",style={'textAlign':'center'}),       
		html.H6(f"{trending_family_name[3]}", className="text-nowrap fw-bold",style={'textAlign':'center'}),
	]),
	], class_name="border-start border-warning border-5 card border-primary mb-0 max-width: 60rem;"
	), class_name="text-left m-4",
)

card5 = dbc.Card(
	dbc.CardBody(
		[
			html.Div([
		html.H5(f"Trend #5", className="text-nowrap text-warning fw-bold",style={'textAlign':'center'}),       
		html.H6(f"{trending_family_name[4]}", className="text-nowrap fw-bold",style={'textAlign':'center'}),
	]),
	], class_name="border-start border-warning border-5 card border-primary mb-0 max-width: 60rem;"
	), class_name="text-left m-4",
)


    ##new ransomware group

rg1 = dbc.Card(
	dbc.CardBody(
		[
			html.Div([
		html.H5(f"New #1", className="text-nowrap text-warning fw-bold",style={'textAlign':'center'}),       
		html.H6(f"Freecivilian", className="text-nowrap fw-bold",style={'textAlign':'center'}),
	]),
	], class_name="border-start border-warning border-5 card border-primary mb-0 max-width: 60rem;"
	), class_name="text-left m-4",
)

rg2 = dbc.Card(
	dbc.CardBody(
		[
			html.Div([
		html.H5(f"New #2", className="text-nowrap text-warning fw-bold",style={'textAlign':'center'}),       
		html.H6(f"Nokoyawa", className="text-nowrap fw-bold",style={'textAlign':'center'}),
	]),
	], class_name="border-start border-warning border-5 card border-primary mb-0 max-width: 60rem;"
	), class_name="text-left m-4",
)

rg3 = dbc.Card(
	dbc.CardBody(
		[
			html.Div([
		html.H5(f"New #3", className="text-nowrap text-warning fw-bold",style={'textAlign':'center'}),       
		html.H6(f"Vendatta", className="text-nowrap fw-bold",style={'textAlign':'center'}),
	]),
	], class_name="border-start border-warning border-5 card border-primary mb-0 max-width: 60rem;"
	), class_name="text-left m-4",
)

rg4 = dbc.Card(
	dbc.CardBody(
		[
			html.Div([
		html.H5(f"New #4", className="text-nowrap text-warning fw-bold",style={'textAlign':'center'}),       
		html.H6(f"Medusa", className="text-nowrap fw-bold",style={'textAlign':'center'}),
	]),
	], class_name="border-start border-warning border-5 card border-primary mb-0 max-width: 60rem;"
	), class_name="text-left m-4",
)

rg5 = dbc.Card(
	dbc.CardBody(
		[
			html.Div([
		html.H5(f"New #5", className="text-nowrap text-warning fw-bold",style={'textAlign':'center'}),       
		html.H6(f"N/A", className="text-nowrap fw-bold",style={'textAlign':'center'}),
	]),
	], class_name="border-start border-warning border-5 card border-primary mb-0 max-width: 60rem;"
	), class_name="text-left m-4",
)

card1_1m = dbc.Card(
	dbc.CardBody(
		[
			html.Div([
		html.H5(f"Trending #1", className="text-nowrap text-warning fw-bold",style={'textAlign':'center'}),       
		html.H6(f"N/A", className="text-nowrap fw-bold",style={'textAlign':'center'}),
	]),
	], class_name="border-start border-warning border-5 card border-primary mb-0 max-width: 60rem;"
	), class_name="text-left m-4",
)

card2_1m = dbc.Card(
	dbc.CardBody(
		[
			html.Div([
		html.H5(f"Trending #2", className="text-nowrap text-warning fw-bold",style={'textAlign':'center'}),       
		html.H6(f"N/A", className="text-nowrap fw-bold",style={'textAlign':'center'}),
	]),
	], class_name="border-start border-warning border-5 card border-primary mb-0 max-width: 60rem;"
	), class_name="text-left m-4",
)

card3_1m = dbc.Card(
	dbc.CardBody(
		[
			html.Div([
		html.H5(f"Trending #3", className="text-nowrap text-warning fw-bold",style={'textAlign':'center'}),       
		html.H6(f"N/A", className="text-nowrap fw-bold",style={'textAlign':'center'}),
	]),
	], class_name="border-start border-warning border-5 card border-primary mb-0 max-width: 60rem;"
	), class_name="text-left m-4",
)

card4_1m = dbc.Card(
	dbc.CardBody(
		[
			html.Div([
		html.H5(f"Trending #4", className="text-nowrap text-warning fw-bold",style={'textAlign':'center'}),       
		html.H6(f"N/A", className="text-nowrap fw-bold",style={'textAlign':'center'}),
	]),
	], class_name="border-start border-warning border-5 card border-primary mb-0 max-width: 60rem;"
	), class_name="text-left m-4",
)

card5_1m = dbc.Card(
	dbc.CardBody(
		[
			html.Div([
		html.H5(f"Trending #5", className="text-nowrap text-warning fw-bold",style={'textAlign':'center'}),       
		html.H6(f"N/A", className="text-nowrap fw-bold",style={'textAlign':'center'}),
	]),
	], class_name="border-start border-warning border-5 card border-primary mb-0 max-width: 60rem;"
	), class_name="text-left m-4",
)

card1_3m = dbc.Card(
	dbc.CardBody(
		[
			html.Div([
		html.H5(f"Trending #1", className="text-nowrap text-warning fw-bold",style={'textAlign':'center'}),       
		html.H6(f"N/A", className="text-nowrap fw-bold",style={'textAlign':'center'}),
	]),
	], class_name="border-start border-warning border-5 card border-primary mb-0 max-width: 60rem;"
	), class_name="text-left m-4",
)

card2_3m = dbc.Card(
	dbc.CardBody(
		[
			html.Div([
		html.H5(f"Trending #2", className="text-nowrap text-warning fw-bold",style={'textAlign':'center'}),       
		html.H6(f"N/A", className="text-nowrap fw-bold",style={'textAlign':'center'}),
	]),
	], class_name="border-start border-warning border-5 card border-primary mb-0 max-width: 60rem;"
	), class_name="text-left m-4",
)

card3_3m = dbc.Card(
	dbc.CardBody(
		[
			html.Div([
		html.H5(f"Trending #3", className="text-nowrap text-warning fw-bold",style={'textAlign':'center'}),       
		html.H6(f"N/A", className="text-nowrap fw-bold",style={'textAlign':'center'}),
	]),
	], class_name="border-start border-warning border-5 card border-primary mb-0 max-width: 60rem;"
	), class_name="text-left m-4",
)


card4_3m = dbc.Card(
	dbc.CardBody(
		[
			html.Div([
		html.H5(f"Trending #4", className="text-nowrap text-warning fw-bold",style={'textAlign':'center'}),       
		html.H6(f"N/A", className="text-nowrap fw-bold",style={'textAlign':'center'}),
	]),
	], class_name="border-start border-warning border-5 card border-primary mb-0 max-width: 60rem;"
	), class_name="text-left m-4",
)


card5_3m = dbc.Card(
	dbc.CardBody(
		[
			html.Div([
		html.H5(f"Trending #5", className="text-nowrap text-warning fw-bold",style={'textAlign':'center'}),       
		html.H6(f"N/A", className="text-nowrap fw-bold",style={'textAlign':'center'}),
	]),
	], class_name="border-start border-warning border-5 card border-primary mb-0 max-width: 60rem;"
	), class_name="text-left m-4",
)

card1_6m = dbc.Card(
	dbc.CardBody(
		[
			html.Div([
		html.H5(f"Trending #1", className="text-nowrap text-warning fw-bold",style={'textAlign':'center'}),       
		html.H6(f"N/A", className="text-nowrap fw-bold",style={'textAlign':'center'}),
	]),
	], class_name="border-start border-warning border-5 card border-primary mb-0 max-width: 60rem;"
	), class_name="text-left m-4",
)

card2_6m = dbc.Card(
	dbc.CardBody(
		[
			html.Div([
		html.H5(f"Trending #2", className="text-nowrap text-warning fw-bold",style={'textAlign':'center'}),       
		html.H6(f"N/A", className="text-nowrap fw-bold",style={'textAlign':'center'}),
	]),
	], class_name="border-start border-warning border-5 card border-primary mb-0 max-width: 60rem;"
	), class_name="text-left m-4",
)

card3_6m = dbc.Card(
	dbc.CardBody(
		[
			html.Div([
		html.H5(f"Trending #3", className="text-nowrap text-warning fw-bold",style={'textAlign':'center'}),       
		html.H6(f"N/A", className="text-nowrap fw-bold",style={'textAlign':'center'}),
	]),
	], class_name="border-start border-warning border-5 card border-primary mb-0 max-width: 60rem;"
	), class_name="text-left m-4",
)

card4_6m = dbc.Card(
	dbc.CardBody(
		[
			html.Div([
		html.H5(f"Trending #4", className="text-nowrap text-warning fw-bold",style={'textAlign':'center'}),       
		html.H6(f"N/A", className="text-nowrap fw-bold",style={'textAlign':'center'}),
	]),
	], class_name="border-start border-warning border-5 card border-primary mb-0 max-width: 60rem;"
	), class_name="text-left m-4",
)

card5_6m = dbc.Card(
	dbc.CardBody(
		[
			html.Div([
		html.H5(f"Trending #5", className="text-nowrap text-warning fw-bold",style={'textAlign':'center'}),       
		html.H6(f"N/A", className="text-nowrap fw-bold",style={'textAlign':'center'}),
	]),
	], class_name="border-start border-warning border-5 card border-primary mb-0 max-width: 60rem;"
	), class_name="text-left m-4",
)

header_logo_time_layout = dbc.Row([    
	dbc.Col([
		html.Div(html.Img(src=pil_img,className="img-thumbnail",alt="Responsive image",style={
				'height': '60%',
				'width': '80%',
				'display':'inline-block'
			}),style={'ImgAlign' : 'left'})], md=2),   
	dbc.Col([
		html.H1(html.Div("KUMAON MK1", style={'textAlign' : 'center'}, className="text-warning"))], md=7),
	dbc.Col([
		html.H5(html.Div(f'Date: {datetime.datetime.now().strftime("%d-%m-%Y")}\nTime: {datetime.datetime.now().strftime("%H:%M")}', style={'textAlign' : 'right'}, className="text-warning"))], md=2,width={'offset' : 1})
],align='end',justify='start')


strategic_intelligence_layout = dbc.Row([
	dbc.Col([
			html.H5(html.Label(['STRATEGIC INTELLIGENCE']), style={'textAlign' : 'left'}, className="fw-bold" ),
        	html.Div(id='the_card_strategic_1'),
    ],align='left'),  
],align='start')



operational_intelligence_layout = [
	dbc.Row([
		dbc.Col([
			html.H4("OPERATIONAL INTELLIGENCE", style={'textAlign' : 'left'}, className="fw-bold margin-bottom: 25px")
		], width = 12)
	]),
	dbc.Row([
		dbc.Col([
			html.H5(html.Mark("TRENDING"), style={'textAlign' : 'left'}, className="fw-bold")
		], width = 12)
	]),
	dbc.Row([
		dbc.Col(card1),
		dbc.Col(card2),
		dbc.Col(card3),
		dbc.Col(card4),
		dbc.Col(card5)
	]),
	dbc.Row([
		dbc.Col([
			html.H5(html.Mark("NEW RANSOMWARE GROUPS"), style={'textAlign' : 'left'}, className="fw-bold")
		], width = 12)
	]),
	dbc.Row([
		dbc.Col(rg1),
		dbc.Col(rg2),
		dbc.Col(rg3),
		dbc.Col(rg4),
		dbc.Col(rg5)
	]),
    dbc.Row([
		html.H5(html.Mark(['FAMILY']), style={'textAlign' : 'left'}, className="fw-bold"),
        html.Div([html.P('')]),
			dcc.Dropdown(
				trending_family_name,
				id = 'my_dropdown_2',
				value=trending_family_name[0],
				multi=False,
				clearable=False,
				style={"width":"50%", "color":"black"})
	]),
    dbc.Row([
		dbc.Col([
			html.H5(html.Mark(['INTENT & CAPABILITY']), style={'textAlign' : 'left'}, className="fw-bold" ),
        	html.Div(id='the_card_intent')	
	])
	]),
	dbc.Row([
#slider and bar graph
		dbc.Col([
			html.Div([
			dbc.Row([html.Div([html.P('')])]),
			html.Div([
				html.H5(html.Mark(['EXTORTION TIMELINE']), style={'textAlign' : 'left'}, className="fw-bold"),
				html.P(),
				dcc.RangeSlider(
					id='my_range_slider',
					marks=month_dict,

					min=1,
					max=7,
					value=[3,4],
					dots=False,
					allowCross=True,
					disabled=False,
					#pushable=1,
					updatemode='mouseup',
					included=True,
					vertical=False,
					verticalHeight=900,
					className='None',
					#tooltip={'always_visible': False, 'placement':'bottom'},
				),
				html.Div([dcc.Graph(id='our_graph')])
			])
			]),
		], width={'offset': 30}),
	]),
     
]

malware_analysis = [
	dbc.Row([
		dbc.Col([
			html.H4("MALWARE", style={'textAlign' : 'left'}, className="fw-bold margin-bottom: 25px")
		], width = 12)
	]),
	dbc.Row([
		dbc.Col([
			html.H5(html.Mark("1-MONTH TRENDING"), style={'textAlign' : 'left'}, className="fw-bold")
		], width = 12)
	]),
	dbc.Row([
		dbc.Col(card1_1m),
		dbc.Col(card2_1m),
		dbc.Col(card3_1m),
		dbc.Col(card4_1m),
		dbc.Col(card5_1m)	
	]),
	dbc.Row([
		dbc.Col([
			html.H5(html.Mark("3-MONTH TRENDING"), style={'textAlign' : 'left'}, className="fw-bold")
		], width = 12)
	]),
	dbc.Row([
		dbc.Col(card1_3m),
		dbc.Col(card2_3m),
		dbc.Col(card3_3m),
		dbc.Col(card4_3m),
		dbc.Col(card5_3m)	
	]),
	dbc.Row([
		dbc.Col([
			html.H5(html.Mark("6-MONTH TRENDING"), style={'textAlign' : 'left'}, className="fw-bold")
		], width = 12)
	]),
	dbc.Row([
		dbc.Col(card1_6m),
		dbc.Col(card2_6m),
		dbc.Col(card3_6m),
		dbc.Col(card4_6m),
		dbc.Col(card5_6m)	
	]),	
]



# pie_chart_targets_layout = dbc.Row([   
# 		dbc.Col([
# 			html.Div([
# 			html.Div([
# 				html.H5(html.Label(['TARGETS']), style={'textAlign' : 'left'}, className="fw-bold" ),
# 				dcc.Dropdown(
# 					df.columns,
# 					id = 'my_dropdown',
# 					value=df.columns[0],
# 					multi=False,
# 					clearable=False,
# 					style={"width":"50%", "color":"black"}
# 				),
# 			]),
#             dbc.Row([html.Div([html.P('')])]),
#             dbc.Row([html.Div([html.P('')])]),
#             dbc.Row([html.Div([html.P('')])]),
#             dbc.Row([html.Div([html.P('')])]),
#             dbc.Row([html.Div([html.P('')])]),
#             dbc.Row([html.Div([html.P('')])]),
# 			html.Div([dcc.Graph(id='the_graph')]),
# 			])
# 		], align="start"),


# ])



tactical_vuln_intelligence_layout =  dbc.Row([
    dbc.Col([
        html.H4("TACTICAL INTELLIGENCE", style={'textAlign' : 'left'}, className="fw-bold margin-bottom: 25px"),
        html.Div(id='the_card_tactic')	
    ],align='left'),
    dbc.Col([
      	html.H4("VULNERABILITY INTELLIGENCE", style={'textAlign' : 'left'}, className="fw-bold margin-bottom: 25px"),
        dbc.Row([html.Div([html.P('')])]),
        html.Div(id='the_card_vuln'),
		html.Div(id='the_alert'),
	])
    ],align='start')


attack_by_sector_attack_vector = dbc.Row([
	dbc.Col([
		html.H4("ATTACK BY SECTOR", style={'textAlign' : 'left'}, className="fw-bold margin-bottom: 25px"),
		dcc.Graph(id='the_piechart_graph')
	],align="left",width=6),
    # dbc.Col([
	# 	html.H4("ATTACK VECTOR", style={'textAlign' : 'left'}, className="fw-bold margin-bottom: 25px"),
	# 	dcc.Graph(id='the_donut_graph')
	# ],align='right',width=6)
	dbc.Col([
		html.H4("ATTACK VECTOR", style={'textAlign' : 'left'}, className="fw-bold margin-bottom: 25px"),
		html.Div(id='the_attack_vector')
	],align='right',width=6)
])


chained_callback_attack_by_sector = [
    dbc.Row([
		html.H5(html.Mark(['FAMILY']), style={'textAlign' : 'left'}, className="fw-bold"),
        html.Div([html.P('')]),
			dcc.Dropdown(
				sector_unique_family,
				id = 'my_dropdown_3',
				value=sector_unique_family[0],
				multi=False,
				clearable=False,
				style={"width":"50%", "color":"black"})
	]),
	dbc.Row([
#slider and bar graph
		dbc.Col([
			html.Div([
			dbc.Row([html.Div([html.P('')])]),
			html.Div([
				html.H5(html.Mark(['AFFECTED SECTORS BY RANSOMWARE']), style={'textAlign' : 'left'}, className="fw-bold"),
				html.P(),
				dcc.RangeSlider(
					id='my_range_slider_1',
					marks=sector_month_dict,
					min=1,
					max=5,
					value=[3,4],
					dots=False,
					allowCross=True,
					disabled=False,
					#pushable=1,
					updatemode='mouseup',
					included=True,
					vertical=False,
					verticalHeight=900,
					className='None',
					#tooltip={'always_visible': False, 'placement':'bottom'},
				),
				html.Div([dcc.Graph(id='our_graph_sector')])
			])
			]),
		], width={'offset': 30}),
	]),
     
]

funnel_chart_layout = dbc.Row([
	dbc.Col([
		html.H5(html.Mark("1 Month"), style={'textAlign' : 'left'}, className="fw-bold"),
		html.Div([
			dcc.Graph(
				figure = funnelchart()
			)
		])   
	]
        #,md=5, width = {'offset':0, 'size':0}, align = "start"
            ),
	dbc.Col([
		html.H5(html.Mark("3 Month"), style={'textAlign' : 'left'}, className="fw-bold"),
		html.Div([
			dcc.Graph(
				figure = funnelchart2()
			)
		])   
	]),
    # , md=5, width = {'offset':0, 'size':0}, align = "left"
	dbc.Col([
		html.H5(html.Mark("6 Month"), style={'textAlign' : 'left'}, className="fw-bold"),
		html.Div([
			dcc.Graph(
				figure = funnelchart3()
			)
		])   
	]
    #   , md=5, width = {'offset':0, 'size':1}, align ="left"
	),
],className='g-0')

		


email_alert_layout = [
    dbc.Row([
    	dbc.Col('Would you like to set up email to send trending and new ransomware groups?',className='mt-4 mb-2'),
        dbc.Col('Would you like to get additional threat intelligence data?',id='addtional-text',className='mt-4 mb-2')
    ]),
    dbc.Row([
    	dbc.Col(dcc.RadioItems(id='alert-permission', options=['No','Yes, email alerts'], value='No',style={"margin-left": "15px"}),className="mt-1"),
        dbc.Col(dcc.RadioItems(id='additional-info', options=['No','Yes, email alerts'], value='No'),className="mt-1")
    ]),
    dbc.Row([
    	dbc.Col(dbc.Input(id="input", placeholder="Please provide an email id", type="text")),
        dbc.Col(dbc.Input(id="additional-input", placeholder="Please provide an email id", type="text",className="w-75"))
    ]),
    dbc.Row([
    	dbc.Col(dbc.Button(
            "Get update via email", id="example-button", className="mt-4 bg-light border border-dark", n_clicks=0
    	)),
     	dbc.Col(dbc.Button(
            "Submit", id="additonal-button", className="mt-4 bg-light border border-dark", n_clicks=0
    	))
    ]),
    dbc.Row([
     	dbc.Col(id="example-output",className='ms-1 mt-4 mb-2'),
        dbc.Col(id="additional-output",className='ms-1 mt-4 mb-2')
    ]),
]

page_1_layout = dbc.Container([
	html.Div([
		header_logo_time_layout,
        dbc.Row([html.Div([html.P('')])]),
        dbc.Row([html.Div([html.P('')])]),
        dbc.Row([html.Div([html.P('')])]),
		operational_intelligence_layout[0],
        dbc.Row([html.Div([html.P('')])]),
		operational_intelligence_layout[1],
		operational_intelligence_layout[2],
        dbc.Row([html.Div([html.P('')])]),
		operational_intelligence_layout[3],
		operational_intelligence_layout[4],
        dbc.Row([html.Div([html.P('')])]),
		operational_intelligence_layout[5],
		dbc.Row([html.Div([html.P('')])]),
        dbc.Row([html.Div([html.P('')])]),
        operational_intelligence_layout[6],
        operational_intelligence_layout[7],
        dbc.Row([html.Div([html.P('')])]),
        dbc.Row([html.Div([html.P('')])]),
		strategic_intelligence_layout,
        dbc.Row([
            dbc.Col([
                html.Div(
                    [
                        dbc.Button(
                            "Page2",
                            href="/page-2",
                            external_link=True,
                            color="info",
                            className="me-1",
                            active=True,
                            outline=True,
                        ),
						dbc.Button(
							"Page3",
							href="/page-3",
							external_link=True,
							color="info",
							className="me-1",
							active=True,
							outline=True,
						),
                    ]
                )
            ],align='center',style={'textAlign':'center'}),
        ],align='end',justify='center'), 
	],className="pad-row")
])    


page_2_layout = dbc.Container([
    header_logo_time_layout,
	dbc.Row([html.Div([html.P('')])]),
    dbc.Row([html.Div([html.P('')])]),
    dbc.Row([
		html.H5(html.Mark(['FAMILY']), style={'textAlign' : 'left'}, className="fw-bold"),
        html.Div([html.P('')]),
			dcc.Dropdown(
				trending_family_name,
				id = 'my_dropdown_2',
				value=trending_family_name[0],
				multi=False,
				clearable=False,
				style={"width":"50%", "color":"black"})
	]),
    dbc.Row([html.Div([html.P('')])]),
    tactical_vuln_intelligence_layout,
	dbc.Row([html.Div([html.P('')])]),
    dbc.Row([html.Div([html.P('')])]),
    attack_by_sector_attack_vector,
    dbc.Row([html.Div([html.P('')])]),
    dbc.Row([html.Div([html.P('')])]),
    chained_callback_attack_by_sector[0],
    dbc.Row([html.Div([html.P('')])]),
    chained_callback_attack_by_sector[1],
    dbc.Row([html.Div([html.P('')])]),
	dbc.Row([
		dbc.Col([
			html.Div(
				[
					dbc.Button(
						"Page3",
						href="/page-3",
						external_link=True,
						color="info",
						className="me-1",
						active=True,
						outline=True,
					),
					dbc.Button(
							"Page1",
							href="/page-1",
							external_link=True,
							color="info",
							className="me-1",
							active=True,
							outline=True,
						),
				]
			)
		],align='center',style={'textAlign':'center'}),
	],align='end',justify='center'),   
])



page_3_layout = dbc.Container([
    header_logo_time_layout,
	dbc.Row([html.Div([html.P('')])]),
    dbc.Row([html.Div([html.P('')])]),
    dbc.Row([html.Div([html.P('')])]),
    malware_analysis[0],
    dbc.Row([html.Div([html.P('')])]),
    malware_analysis[1],
    malware_analysis[2],
    dbc.Row([html.Div([html.P('')])]),
    malware_analysis[3],
    malware_analysis[4],
    dbc.Row([html.Div([html.P('')])]),
    malware_analysis[5],
    malware_analysis[6],
    dbc.Row([html.Div([html.P('')])]),
    dbc.Row([html.Div([html.P('')])]),
    funnel_chart_layout,
    dbc.Row([html.Div([html.P('')])]),
    dbc.Row([html.Div([html.P('')])]),
	email_alert_layout[0],
	email_alert_layout[1],
	email_alert_layout[2],
	email_alert_layout[3],
	email_alert_layout[4],
	dbc.Row([
		dbc.Col([
			html.Div(
				[
					dbc.Button(
						"Page2",
						href="/page-2",
						external_link=True,
						color="info",
						className="me-1",
						active=True,
						outline=True,
					),
					dbc.Button(
							"Page1",
							href="/page-2",
							external_link=True,
							color="info",
							className="me-1",
							active=True,
							outline=True,
						),
				]
			)
		],align='center',style={'textAlign':'center'}),
	],align='end',justify='center'),   
])





@app.callback(
	Output('page-content', 'children'),
	[Input('url', 'pathname')]
)

def display_page(pathname):
	if pathname == '/page-1':
		return page_1_layout
	elif pathname == '/page-2':
		return page_2_layout
	elif pathname == '/page-3':
		return page_3_layout
	





#run the app
if __name__ == '__main__':
    app.run_server(debug = True)
