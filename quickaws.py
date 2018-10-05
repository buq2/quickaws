# Quick AWS module for fast execution of scripts at aws

import boto3
import tarfile
import os.path
import time
import os
import math
import base64
from dateutil import parser
import datetime
import pytz

class QuickAws(object):
	def __init__(self,
		files_to_upload = [],
		result_files = [],
		usercommand = '',
		tarname = 'data.tar.gz',
		result_tarname = 'result.tar.gz',
		bucket_name = 'buq2-ml-bucket',
		bucket_location = 'eu-central-1',
		instance_location = 'cheapest', #for example 'eu-central-1' or 'cheapest'
		instance_zone = '',
		use_spot_instance = False,
		max_hourly_price = None,
		keyfilename = 'key.pem',
		install_anaconda = False,
		installed_anaconda_version = 'Anaconda3-5.2.0-Linux-x86_64',
		update_anaconda = False,
		keyname = 'analysis-ec2-instance-key',
		instancetype = 't2.micro', #'c5.large'#'t2.micro'
		instance_image_id = '', # 'ami-0f5dbc86dd9cbf7a8'=base, 'ami-031723628dc6a197d'=anaconda3-buq2
		image_description = '*ami-031723628dc6a197d*', #*Anaconda3 5.2.0*Amazon*',
		iam_role_name = 'buq2-ml-bucket-access-role',
		iam_policy_name = 'buq2-ml-bucket-access-policy',
		iam_instance_profile_name = 'buq2-ml-bucket-access-profile',
		monitoring = False,
		jupyterfile = '',
		do_not_upload = False,
		shutdown_behavior='terminate',
		do_not_shutdown = False,
		terminate_after_seconds = 86400,
		console_output_filename = 'console_output.txt',
		tags=['quickaws']
		):
		'''QuickAws runs usercommand on ec2 instance as quickly as possible and this way saves money.

		Parameters
		----------
		files_to_upload : list
			List of filenames from local computer which should be uploaded to the instance
		result_files : list
			List of filenames which should be fetched from the instance after running the usercommand
		usercommand : string
			Usercommand which is run after setting up the instance and loading the files to the instance.
			If empty and jupyter file is specified, will be automatically generated.
		tarname : string
			Name of archive to which files are stored before running the instance
		result_tarname : string
			Name of the resulting archive which is uploaded to s3
		bucket_name : string
			Name of the s3 bucket to which files will be stored
		bucket_location : string
			Location of the s3 bucket
		instance_location : string
			Instance location as AWS region string (for example 'eu-central-1'). If 'cheapest', cheapest instance location will be searched
		instance_zone : string
			If use_spot_instance is used, full instance location + zone. Can be left empty if instance_location='cheapest'
		use_spot_instance : bool
			If true, spot instance will be launched instead of normal instance
		max_hourly_price : double
			Maximum hourly price for spot instance. If None, on demand price will be used
		keyfilename : string
			Name of the private key file which is used to create access rights to the instance
		install_anaconda : bool
			If true, anaconda will be installed
		installed_anaconda_version : string
			Anaconda version which should be installed
		update_anaconda : bool
			If true, anaconda is automatically updated before running usercommand
		keyname : string
			Name of the key created to aws
		instancetype : string
			Type of aws ec2 instance to launch. Default 't2.micro'
		instance_image_id : string
			Which image is used to create the instance. Can be left empty if image_description is used
		image_description : string
			AMI search string
		iam_role_name : string
			IAM role name
		iam_policy_name : string
			IAM policy name
		iam_instance_profile_name : string
			IAM instance profile name
		monitoring : bool
			If true, ec2 monitoring will be enabled and additional charges may apply
		jupyterfile : string
			Filename of jupyter file. If given jupyter file is automatically run and resulting jupyter file uploaded to s3.
		do_not_upload : bool
			If true, files will not be uploaded to s3 before instance launch.
			Useful when files are already in s3
		shutdown_behavior : string
			'terminate' or 'stop'. What happens to instance when it is shut down
		do_not_shutdown : bool
			If true, instance will not be shut down automatically
		terminate_after_seconds : int
			Maximum run time of the instance in seconds. Default 86400
		console_output_filename : string
			Name of console output file. Default 'console_output.txt'
		tags : list
			Tag used for created resources. Default ['quickaws']
		'''

		self.instance_price_per_hour = 0
		if instance_location == 'cheapest':
			# Find cheapest location for the instance type
			print('Finding cheapest {spot}instance location'.format(spot='spot ' if use_spot_instance else ''))
			if not use_spot_instance:
				locinfo = CheapestEc2Region(instancetype)
				self.instance_price_per_hour = locinfo['price']
				instance_location = locinfo['region'][0]
			else:
				locinfo = CheapestSpotZone(instancetype)
				instance_location = locinfo['region'][0]
				instance_zone = locinfo['zone'][0]
				self.instance_price_per_hour = locinfo['price']

				resp = CheapestEc2Region(instancetype)
				ondemand_price = resp['price']
				ondemand_region = resp['region']
				if not max_hourly_price:
					max_hourly_price = ondemand_price 
				cheapest_on_demand_string = '\nCheapest on demand {price}USD/h at {location}'.format(price=ondemand_price,location=ondemand_region)

			print('Cheapest {type} {spot}instance is located at {location} with price {price}USD/h{comparison}'.format(
				spot='spot ' if use_spot_instance else '',
				type=instancetype,
				location=instance_zone,
				price=locinfo['price'],
				comparison=cheapest_on_demand_string if use_spot_instance else ''))

		if jupyterfile:
			# We are running jupyter file

			if not usercommand:
				# Usercommand was not given, create it automatically
				result_files.append(console_output_filename)
				usercommand = 'jupyter nbconvert --ExecutePreprocessor.timeout={terminate_after_seconds} --to notebook --execute {jupyterfile} --output {jupyterfile}.result.ipynb >>{console_output_filename} 2>&1'.format(jupyterfile=jupyterfile,terminate_after_seconds=terminate_after_seconds,console_output_filename=console_output_filename)

				# Add resulting jupyter file to files to be transferred from the instance
				result_files.append('{jupyterfile}.result.ipynb'.format(jupyterfile=jupyterfile))

			# Add the jupyter file to files to be uploaded to the instance
			files_to_upload.append(jupyterfile)

		self.files_to_upload = files_to_upload
		self.result_files = result_files
		self.usercommand = usercommand
		self.tarname = tarname
		self.result_tarname = result_tarname
		self.bucket_name = bucket_name
		self.bucket_location = bucket_location
		self.instance_location = instance_location
		self.keyfilename = keyfilename
		self.install_anaconda = install_anaconda
		self.installed_anaconda_version = installed_anaconda_version
		self.update_anaconda = update_anaconda
		self.keyname = keyname
		self.instancetype = instancetype
		self.instance_image_id = instance_image_id
		self.iam_role_name = iam_role_name
		self.iam_policy_name = iam_policy_name
		self.iam_instance_profile_name = iam_instance_profile_name
		self.monitoring = monitoring
		#self.jupyterfile = jupyterfile
		self.do_not_upload = do_not_upload
		self.shutdown_behavior = shutdown_behavior
		self.do_not_shutdown = do_not_shutdown
		self.terminate_after_seconds = terminate_after_seconds
		self.max_hourly_price = max_hourly_price
		self.use_spot_instance = use_spot_instance
		self.image_description = image_description
		self.tags = tags
		self.instance_zone = instance_zone

		self.instance = None
		self.spot_request_id = None
		self.instance_terminate_time = None
		self.instance_start_time = None
		self.start_time = None #time when start was called
		self.finish_time = None #time when call to start ended

	def _tarFiles(self):
		# Tar data

		tar = tarfile.open(self.tarname, "w:gz")
		for f in self.files_to_upload:
			if os.path.isfile(f) or os.path.isdir(f):
				tar.add(f)
			else:
				print('file not found for tarring: %s' % f)
		tar.close()

	def _uploadToS3(self):
		# Upload data to aws

		s3 = boto3.client('s3')
		try:
			s3.create_bucket(Bucket=self.bucket_name,
								CreateBucketConfiguration={'LocationConstraint': self.bucket_location})
		except:
			#Bucket probably already exists
			pass

		s3.upload_file(self.tarname, self.bucket_name, self.tarname)

	def _createKeys(self):
		# Create aws instance keys
		ec2 = boto3.client('ec2', region_name=self.instance_location)

		# Create keys for accessing the server, if key not present
		if not os.path.isfile(self.keyfilename):
			outfile = open(self.keyfilename,'w')
			key_pair = ec2.create_key_pair(KeyName=self.keyname)
			key_pair_out = str(key_pair.key_material)
			outfile.write(key_pair_out)
			outfile.close()
			print('Created key pair {name}. Private key in file {filename}'.format(name=self.keyname,filename=self.keyfilename))
		else:
			print('Keyfile {keyfilename} already exist, using existing key'.format(keyfilename=self.keyfilename))

			# Read private key
			keyfile = open(self.keyfilename,'r')
			pem_data = keyfile.read().encode()
			keyfile.close()

			# Extract public key
			from cryptography.hazmat.backends import default_backend
			from cryptography.hazmat.primitives.serialization import load_pem_private_key
			import cryptography.hazmat.primitives.serialization as serialization
			key = load_pem_private_key(pem_data, password=None, backend=default_backend())
			public = key.public_key()
			public_str = public.public_bytes(encoding=serialization.Encoding.OpenSSH, format=serialization.PublicFormat.OpenSSH)

			try:
				ec2.import_key_pair(
					KeyName=self.keyname,
					PublicKeyMaterial=public_str
				)
				print('Imported key pair {name} from file {file}'.format(name=self.keyname, file=self.keyfilename))
			except ec2.exceptions.ClientError as e:
				if e.response['Error']['Code'] == 'InvalidKeyPair.Duplicate':
					# Already exist, all fine
					print('Key pair with name {name} already exist. Using it'.format(name=self.keyname))
				else:
					raise e
			

	def _anacondaInstallString(self):
		anaconda_install_string = ''
		if self.install_anaconda:
			anaconda_install_string = '''
				wget https://repo.anaconda.com/archive/{installed_anaconda_version}.sh -O ~/anaconda.sh
				bash ~/anaconda.sh -b -p $HOME/anaconda
				'''.format(installed_anaconda_version=self.installed_anaconda_version)
		return anaconda_install_string

	def _anacondaUpdateString(self):
		anaconda_update_string = ''
		if self.update_anaconda:
			anaconda_update_string = '''
				conda update --yes -n root conda
				conda update --yes --all
				'''
		return anaconda_update_string

	def _shutdownString(self):
		shutdown_string = 'sudo shutdown -h now'
		if self.do_not_shutdown:
			shutdown_string = ''
		return shutdown_string

	def _userDataString(self):
		anaconda_install_string = self._anacondaInstallString()
		anaconda_update_string = self._anacondaUpdateString()
		shutdown_string = self._shutdownString()

		user_data = '''#!/bin/bash
		aws s3 cp s3://{bucket_name}/{tarname} .
		tar -zxvf {tarname}
		{anaconda_install_string}
		export PATH="/root/anaconda/bin:$PATH"
		{anaconda_update_string}
		{usercommand}
		tar cfz {result_tarname} {result_files}
		aws s3 cp {result_tarname} s3://{bucket_name}/{result_tarname}
		{shutdown_string}'''.format(bucket_name=self.bucket_name,
									tarname=self.tarname,
									result_tarname=self.result_tarname,
									result_files=' '.join(self.result_files),
									usercommand=self.usercommand,
									anaconda_update_string=anaconda_update_string,
									anaconda_install_string=anaconda_install_string,
									shutdown_string=shutdown_string)
		return user_data

	def _createSpotInstance(self):
		user_data = self._userDataString()

		ec2 = boto3.client('ec2', region_name=self.instance_location)
		spot_reqs = ec2.request_spot_instances(
			SpotPrice=str(self.max_hourly_price),
			LaunchSpecification={
				'ImageId':self._searchAmi(),
				'InstanceType':self.instancetype,
				'Placement':{'AvailabilityZone':self.instance_zone},
				'KeyName':self.keyname,
				'UserData':base64.b64encode(user_data.encode("utf-8")).decode("utf-8") ,
				},
			InstanceCount=1,
			)

		self.spot_request_id = spot_reqs['SpotInstanceRequests'][0]['SpotInstanceRequestId']

		print('Created spot request {id}'.format(id=self.spot_request_id))

	def _waitForSpotInstance(self):
		print('Waiting for spot instance request to be fulfilled', end='')
		ec2 = boto3.client('ec2', region_name=self.instance_location)
		spot_wait_sleep = 1
		
		while not self.instance:
			spot_req = ec2.describe_spot_instance_requests(SpotInstanceRequestIds=[self.spot_request_id])['SpotInstanceRequests'][0]

			if spot_req['State'] == 'failed':
				raise Exception('Spot request failed')

			if not 'InstanceId' in spot_req:
				print('.',end='')
				time.sleep(spot_wait_sleep)
			else:
				ec2c = boto3.resource('ec2',region_name='us-east-2')
				self.instance = ec2c.Instance(id=spot_req['InstanceId'])

		print('')
		self.instance.create_tags(Tags=[{'Key':'quickaws','Value':'1'}])
		print('Spot instance fulfilled with instance {id}'.format(id=self.instance.id))

	def _createInstance(self):
		# Create actual instance
		user_data = self._userDataString()

		ec2 = boto3.resource('ec2', region_name=self.instance_location)

		instances = ec2.create_instances(
			ImageId=self._searchAmi(),
			MinCount=1,
			MaxCount=1,
			KeyName=self.keyname,
			InstanceType=self.instancetype,
			Monitoring={'Enabled':self.monitoring},
			InstanceInitiatedShutdownBehavior=self.shutdown_behavior,
			UserData=user_data,
			TagSpecifications=[{'ResourceType': 'instance','Tags': self.tags},
								{'ResourceType': 'volume','Tags': self.tags},]
		)
			
		self.instance = instances[0]
		print("Created instance {0}".format(self.instance.id))

	def _createInstancePermissions(self):
		# Wait until instance is running
		print('Waiting for instance to enter ''running'' state')
		self.instance.wait_until_running()
		print('Instance entered ''running'' state')

		iam = boto3.resource('iam')
		instance_profile = iam.InstanceProfile(self.iam_instance_profile_name)
		try:
			instance_profile.arn
			print('Instance profile {0} already exists. Using it'.format(self.iam_instance_profile_name))
		except:
			# Instance profile does not exist, create it

			# Role has policy to allow access to bucket we created
			policy = r'''{{
				"Version": "2012-10-17",
				"Statement": [
					{{
						"Effect": "Allow",
						"Action": ["s3:ListBucket"],
						"Resource": ["arn:aws:s3:::{bucket_name}"]
					}},
					{{
						"Effect": "Allow",
						"Action": [
							"s3:PutObject",
							"s3:GetObject"
						],
						"Resource": ["arn:aws:s3:::{bucket_name}/*"]
					}}
				]
			}}'''.format(bucket_name=self.bucket_name)

			policy_response = iam.create_policy(
							PolicyName=self.iam_policy_name,
							PolicyDocument=policy,
							Description='quickaws')
			print('Created policy {iam_policy_name}'.format(iam_policy_name=self.iam_policy_name))

			role_policy= r'''{
			"Version": "2012-10-17",
			"Statement": [
				{
				"Effect": "Allow",
				"Principal": {
					"Service": "ec2.amazonaws.com"
				},
				"Action": "sts:AssumeRole"
				}
			]
			}
			'''

			iam.create_role(RoleName=self.iam_role_name,
						AssumeRolePolicyDocument=role_policy,
						Description='quickaws')
			print('Created role {0}'.format(self.iam_role_name))

			iam_client = boto3.client('iam')
			iam_client.attach_role_policy(RoleName=self.iam_role_name,
								PolicyArn=policy_response.arn)
			print('Attached policy {0} to role {1}'.format(self.iam_policy_name, self.iam_role_name))

			iam_client.create_instance_profile(InstanceProfileName=self.iam_instance_profile_name)
			print('Created instance profile {0}'.format(self.iam_instance_profile_name))

			iam_client.add_role_to_instance_profile(InstanceProfileName=self.iam_instance_profile_name,
												RoleName=self.iam_role_name)
			print('Added role {0} ro instance profile {1}'.format(self.iam_role_name, self.iam_instance_profile_name))


		ec2_client = boto3.client('ec2', region_name=self.instance_location)
		ec2_client.associate_iam_instance_profile(
			IamInstanceProfile={
				'Arn': instance_profile.arn,
				'Name': instance_profile.name
			},
			InstanceId=self.instance.id)
		print('Associated instance profile {0} with ec2 instance {1}'.format(self.iam_instance_profile_name, self.instance.id))

	def _printLog(self, chars_printed):
		log = self.instance.console_output()
		if 'Output' in log:
			logstr = log['Output']
			print(logstr[chars_printed:-1])
			chars_printed = len(logstr)
		return chars_printed

	def _waitUntilTerminated(self):
		# Wait until instance is terminated
		print('Waiting for instance to terminate')
		chars_printed = 0
		while self.instance.state['Name'] != 'terminated':
			chars_printed = self._printLog(chars_printed)

		self.instance.wait_until_terminated()
		self.instance_terminate_time = datetime.datetime.now(pytz.utc)

		# Print rest of the log
		self._printLog(chars_printed)

		print('Instance terminated')

	def _downloadFromS3(self):
		# Download results from aws

		print('Downloading results from S3')
		s3 = boto3.client('s3')
		s3.download_file(self.bucket_name, self.result_tarname, self.result_tarname)
		print('Files downloaded')

		# Extract downloaded data
		print('Extracting files')
		tar = tarfile.open(self.result_tarname,'r')
		tar.extractall()
		tar.close()

	def _searchAmi(self):
		if self.instance_image_id:
			return self.instance_image_id
		if self.image_description:
			ec2 = boto3.resource("ec2", region_name=self.instance_location)
			filters = [ {
				'Name': 'description',
				'Values': [self.image_description]
			}]
			images = ec2.images.filter(Filters=filters)
			
			latest = None
			for i in images:
				if not latest:
					latest = i
				elif parser.parse(i.creation_date) > parser.parse(latest.creation_date):
					latest = i
			print('Found ami {id} with description: {desc}'.format(id=latest.image_id,desc=latest.description))
			return latest.image_id

	def _recordInstanceStartTime(self):
		self.instance_start_time = self.instance.launch_time

	def _estimatePrice(self):
		time_running = (self.instance_terminate_time - self.instance_start_time).total_seconds()
		total_time = (self.finish_time - self.start_time).total_seconds()
		price = self.instance_price_per_hour
		cost_usd = time_running/60/60*price
		print('Running of instance for {seconds:0.0f}s cost approximately {cost:0.5f}USD'.format(seconds=time_running,cost=cost_usd))
		print('Total run time including setup {seconds:0.0f}'.format(seconds=total_time))


	def start(self):
		self.start_time = datetime.datetime.now(pytz.utc)

		if not self.do_not_upload:
			self._tarFiles()
			self._uploadToS3()
		self._createKeys()

		if self.use_spot_instance:
			self._createSpotInstance()
			self._waitForSpotInstance()
		else:
			self._createInstance()
		self._createInstancePermissions()
		self._recordInstanceStartTime()
		self._waitUntilTerminated()
		self._downloadFromS3()
		self.finish_time = datetime.datetime.now(pytz.utc)
		self._estimatePrice()
		print('Finished')

def CheapestEc2Region(type='t2.micro'):
	#os.environ['AWSPRICING_USE_CACHE'] = '1'
	#os.environ['AWSPRICING_CACHE_MINUTES'] = '10080' #10080 = 1 week

	import awspricing
	ec2_offer = awspricing.offer('AmazonEC2')

	#Cheapest region
	min_price = math.inf
	min_region = []

	#All regions
	all_regions = []

	# Search price for every region
	ec2 = boto3.client('ec2')
	response = ec2.describe_regions()
	for reg in response['Regions']:
		name = reg['RegionName']
		try:
			p = ec2_offer.ondemand_hourly(
				type,
				operating_system='Linux',
				region=name
				)

			all_regions.append({'region':name,'price':p})
			if p < min_price:
				min_price = p
				min_region = [name]
			elif p == min_price:
				min_region.append(name)
		except:
			pass
	return {'region':min_region,'price':min_price,'all_regions':all_regions}

def SpotInstancePrice(region,type):
	client=boto3.client('ec2',region_name='us-east-1')
	prices=client.describe_spot_price_history(InstanceTypes=[type],MaxResults=1,ProductDescriptions=['Linux/UNIX (Amazon VPC)'],AvailabilityZone=region)
	return prices['SpotPriceHistory'][0]

def CheapestSpotZone(type='t2.micro'):
	#Cheapest region
	min_price = math.inf
	min_region = []
	min_zone = []

	# All zones
	all_zones = []

	# Search price for every region
	client = boto3.client('ec2',region_name='us-east-1')
	response = client.describe_regions()

	for reg in response['Regions']:
		regname = reg['RegionName']
		client_reg = boto3.client('ec2',region_name=regname)

		r = client_reg.describe_availability_zones()
		zones = r['AvailabilityZones']
		for zone in zones:

			zonename = zone['ZoneName']

			try:
				prices=client_reg.describe_spot_price_history(InstanceTypes=[type],MaxResults=1,ProductDescriptions=['Linux/UNIX (Amazon VPC)'],AvailabilityZone=zonename)

				p = prices['SpotPriceHistory'][0]['SpotPrice']
				p = float(p)
				all_zones.append({'price':p,'zone':zonename,'region':regname})
				if p < min_price:
					min_price = p
					min_zone = [zonename]
					min_region = [regname]
				elif p == min_price:
					min_zone.append(zonename)
					min_region.append(regname)
			except:
				pass
	return {'zone':min_zone,'price':min_price,'region':min_region,'all_zones':all_zones}
	
