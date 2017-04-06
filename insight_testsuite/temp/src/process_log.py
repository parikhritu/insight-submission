##################################################################
# Ritu Parikh rituparikh94@gmail.com
##################################################################
import pandas as pd
import numpy as np
from datetime import datetime as dt
import datetime
import time
pd.options.mode.chained_assignment = None

start_time = time.time()
##################################################################
# importing and cleaning the data 
##################################################################
while True:
	try:
		df = pd.read_table('log_input/log.txt', delim_whitespace=True, na_values=('-'), usecols=[0,3,5,6,7], names=('Host','TimeStamp','Request','Code','Bytes'), dtype={'Code': object, 'Bytes': object})
	except (UnicodeDecodeError, IndexError):
		print('some dirty public data')
		pass
	else:
		print("Completed data input ------ %s seconds" % (time.time() - start_time))
		break

df.loc[:,5]=  pd.to_datetime(df['TimeStamp'], format='[%d/%b/%Y:%H:%M:%S') 
print("Completed date format translation ------ %s seconds" % (time.time() - start_time))

##################################################################
# general functions used in 4 required and 2 additional features
##################################################################
def printing_datetime_format(oldTimes, justTime):
	#takes dates from Timestamp format and manipulates them 
	#into the desired printing formats
	#Inputs: 
		#oldTimes = date column in Timestamp format
		#justTime = whether output format includes date and time 
					#or just date
		#Output:
			#printTimes = date column in printing format
	parsedTimes=pd.to_datetime(oldTimes, format='%Y-%m-%d %H:%M:%S')
	if (justTime==1):
		printTimes=parsedTimes.dt.strftime('%H:%M:%S -0400')
	else:
		printTimes=parsedTimes.dt.strftime('%d/%b/%Y:%H:%M:%S -0400')
	return printTimes

def find_best_hours(blocklegth, topx, filled):
	#applies rolling sum over set time period, saves the 
	#highest value, and 0s out the times in the period
	#Inputs:
		#blocklength = num seconds summed in rolling window
		#topx = num high values to output
		#filled = data to sum over
	#Outputs:
		#result = matrix of times with highest sums
	result=[0,0]
	for i in range (0,topx):
		time=filled[::-1].rolling(window=blocklegth, min_periods=1).sum()
		pd.Series.sort_values(time, ascending=False, inplace=True)
		result=np.vstack([result, [time.index[0],time[0]]])
		for x in range(0,blocklegth):
		    filled[time.index[0]+datetime.timedelta(0,x)]=0
		i=i+1
	return result

##################################################################
# 4 required features
##################################################################
def top10_active_hosts():
	hosts=df.groupby('Host').size()
	hosts=pd.Series.sort_values(hosts, ascending=False)
	hosts[:10].to_csv('log_output/hosts.txt')
	print("Completed feature 1: Top 10 active hosts ------ %s seconds" % (time.time() - start_time))

def top10_consumed_resources():
	df['Bytes_num']=pd.to_numeric(df['Bytes'], errors='coerce') #make sure all Bytes are numbers
	resources=df.groupby('Request').Bytes_num.sum()
	pd.Series.sort_values(resources, ascending=False, inplace=True)
	df_resources=pd.DataFrame({'Resources':resources.index, 'Bandwidth':resources.index})[:10] #create dataframe to use .replace and prep output format
	df_resources['Resources'].replace(["GET /","POST /","HOST /", " HTTP/1.0"],["/","/","/",""], regex=True, inplace=True)
	df_resources['Resources'].to_csv('log_output/resources.txt',index=False)
	print("Completed feature 2: Top 10 resources consumed ------ %s seconds" % (time.time() - start_time))

def top10_busiest_60mins():
	density = df.groupby(5).size() #col 5 is Timestamp - groupby datetime
	filled=density.resample('1S').asfreq() #fill in all missing seconds
	filled=filled[::-1].rolling(window=3600, min_periods=1).sum() #apply rolling sum over 1h
	pd.Series.sort_values(filled, ascending=False, inplace=True)
	df_top10=pd.DataFrame({'Hour':filled.index, 'Tally':filled.values.astype(int)})[:10] #extract timestamp from index
	df_top10['Hour']=printing_datetime_format(df_top10['Hour'],0) #format timestamp for output format
	df_top10.to_csv('log_output/hours.txt',index=False, header=False)
	print("Completed feature 4: Top 10 busiest 60 minutes ------ %s seconds" % (time.time() - start_time))

def security_breaches():
	df401size=df[df['Code'] == '401'].groupby([5,'Host']).size().reset_index(level=0) #for 401 errors, groupby time and host, make host index
	#the below section is a hackish solution: there are times where multiple 
	#hosts hit a 401 error at the same time, and timestamps cant be resampled 
	#if there are duplicate values in the index. below, we remove all hosts 
	#that hit the 401 error less than 3 times in total. This inadvertantly 
	#also removes the hosts causing the time duplication -- allowing us to resample
	df401size = pd.concat([df401size, df401size.groupby(level=0).size()], axis=1, join_axes=[df401size.index], ignore_index=True) #concat df with number of 401 errors for each host
	_3plus=df401size[df401size[2]>2] #remove all hosts with less than 3 errors
	_3plus.reset_index(level=1, inplace=True) #extract host from index
	_3plus.set_index(0, inplace=True) #set timestamp as index (needed to resample data)
	_3plus=_3plus.resample('1S').asfreq() #fill in missinf time stamps

	failed=_3plus.groupby('Host').rolling(window=20, min_periods=1).sum() #apply rolling window over 20s, sum occurances groupingby host
	with np.errstate(invalid='ignore'):
		locked=failed[failed[1] == 3] #look only at the 3rd occurance for each host
	locked.reset_index(level=0, inplace=True) #remove host from index
	locked.loc[:,3] = locked[0]+datetime.timedelta(0,300) #add 5mins to each time - this will be the max threshold to count attempts that should have been blocked

	df.reset_index(inplace=True) #remove numbers from index
	ignored=[]
	dm = df.as_matrix() #loops took forever so converted to matrix for performance
	for row in locked.itertuples():
		dm_sub=dm[dm[:,1] == row[0]] #get an offending host
		blocked=dm_sub[(dm_sub[:,6] > row[1]) & (dm_sub[:,6] <= row[5]) ][:,0].tolist() #get index.num of attempts that should be blocked for host
		ignored = ignored + blocked

	block=('')
	log = open('log_input/log.txt',encoding='iso-8859-1').readlines()
	for i in ignored: #loop through log file and print all blocked lines
		block = block + log[i]
	blocked=open('log_output/blocked.txt', 'w')
	blocked.write(block)
	blocked.close()
	print("Completed feature 4: Security breaches ------ %s seconds" % (time.time() - start_time))


##################################################################
# 2 additional features
##################################################################	
def busiest_datetimes():
	#this feature identities mutually exclusive periods that have 
	#the highest volume - for example, if July 17th 10:30 is the 
	#beginning of high value period, values from Jul 17 10:30-11:30
	#will not be considered for any other period -- this can be 
	#useful to identify any surges on the fanpage
	density = df.groupby(5).size() #col 5 is timestamp - groupby datetime
	filledDensity=density.resample('1S').asfreq() # fill in all missing seconds
	popular = find_best_hours(3600, 5, filledDensity)[1:11] #find top 5 mutually exclusive 60min datetime chunks
	popular=pd.DataFrame(popular) #extract timestamp from index
	popular[0]=printing_datetime_format(popular[0],0) #format timestamp for printing format
	popular.to_csv('log_output/highvolume_datetime.txt',index=False, header=False)
	print("Completed additional feature 1: Mutually exclusive high traffic periods ------ %s seconds" % (time.time() - start_time))

def popular_times():
	#this feature identifies which mutually exclusive 60 min chunks
	#see the most volume on any given day -- this can be useful
	#to identify peak times on the fanpage and to adjust ad costs
	density = df.groupby(5).size() #col 5 is timestamp - groupby datetime
	density.index = [density.index[i].replace(year=2016, month=7, day=17) for i in range (0,len(density))] #make all date the same - my birthday LOL
	timevolume = density.groupby(density.index).sum() #groupby time
	filledTimeVolume=timevolume.resample('1S').asfreq() #fill in missing seconds
	peekTime = find_best_hours(3600, 5, filledTimeVolume)[1:11] #get top 5 mutually exclusive hours
	peekTime=pd.DataFrame(peekTime) #extract timestamp from index
	peekTime[0]=printing_datetime_format(peekTime[0],1) #format timestamp for printing format
	peekTime.to_csv('log_output/highvolume_time.txt',index=False, header=False)
	print("Completed additional feature 2: Mutually exlcusive popular daily hours ------ %s seconds" % (time.time() - start_time))


##################################################################
# function calls
##################################################################	
top10_active_hosts()
top10_consumed_resources()
top10_busiest_60mins()
security_breaches()
busiest_datetimes()
popular_times()









