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
import uuid

class QuickAws(object):
	def __init__(self,
	    jupyterfile = '',
		instancetype = 't2.micro', #'c5.large'#'t2.micro'
		files_to_upload = [],
		result_files = [],
		use_spot_instance = True,
		instance_location = 'cheapest', #for example 'eu-central-1' or 'cheapest'
		usercommand = '',
		tarname = 'data.tar.gz',
		result_tarname = 'result.tar.gz',
		bucket_name = '',
		delete_bucket = None,
		bucket_location = '',
		instance_zone = '',
		max_hourly_price = None,
		keyfilename = 'key.pem',
		install_anaconda = False,
		installed_anaconda_version = 'Anaconda3-5.2.0-Linux-x86_64',
		update_anaconda = False,
		keyname = '',
		delete_key = None,
		instance_image_id = '', # 'ami-0f5dbc86dd9cbf7a8'=base, 'ami-031723628dc6a197d'=anaconda3-buq2
		image_description = '*Anaconda3 5.2.0*Amazon*',
		image_name = '*',
		iam_role_name = '',
		delete_iam_role = None,
		iam_policy_name = '',
		delete_iam_policy = None,
		iam_instance_profile_name = '',
		delete_iam_instance_profile = None,
		monitoring = False,
		do_not_upload = False,
		shutdown_behavior='terminate',
		do_not_shutdown = False,
		terminate_after_seconds = 86400,
		console_output_filename = 'console_output.txt',
		tags=['quickaws'],
		unsafe_bucket_delete = False,
		perform_cleanup=True,
		):
		'''QuickAws runs usercommand on ec2 instance as quickly as possible and this way saves money.

		Parameters
		----------
		jupyterfile : string
			Filename of jupyter file. If given jupyter file is automatically run and resulting jupyter file uploaded to s3.
		instancetype : string
			Type of aws ec2 instance to launch. Default 't2.micro'
		files_to_upload : list
			List of filenames from local computer which should be uploaded to the instance
		result_files : list
			List of filenames which should be fetched from the instance after running the usercommand
		use_spot_instance : bool
			If true, spot instance will be launched instead of normal instance
		instance_location : string
			Instance location as AWS region string (for example 'eu-central-1'). If 'cheapest', cheapest instance location will be searched
		usercommand : string
			Usercommand which is run after setting up the instance and loading the files to the instance.
			If empty and jupyter file is specified, will be automatically generated.
		tarname : string
			Name of archive to which files are stored before running the instance
		result_tarname : string
			Name of the resulting archive which is uploaded to s3
		bucket_name : string
			Name of the s3 bucket to which files will be stored. If empty, unique bucket name will be generated
		delete_bucket : bool or None
			If True, bucket will be deleted after successfull run. If None and bucket was created, bucket will be deleted
		bucket_location : string
			Location of the s3 bucket (for example 'eu-central-1')
		instance_zone : string
			If use_spot_instance is used, full instance location + zone. Can be left empty if instance_location='cheapest'
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
		delete_key : bool or None
			If true, aws key will be deleted automatically from aws. If None, only automatically generated key fill be deleted
		instance_image_id : string
			Which image is used to create the instance. Can be left empty if image_description is used
		image_description : string
			AMI search string. If instance_image_id is not given, this search string is used to find suitable ami
		image_name : string
			AMI search string
		iam_role_name : string
			IAM role name. If empty, will be automatically created
		delete_iam_role : bool or None
			If None and new iam role is created the role will also be deleted
		iam_policy_name : string
			IAM policy name
		delete_iam_policy : bool
		iam_instance_profile_name : string
			IAM instance profile name
		delete_iam_instance_profile : bool
		monitoring : bool
			If true, advanced ec2 monitoring will be enabled and additional charges may apply
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
			Tag used for created resources. Default ['quickaws']. First tag will be used for auto generated buckets, keys, etc
		unsafe_bucket_delete : bool
			If true, all objects in bucket will be deleted, not just object which were created for this run
		perform_cleanup : bool
			If false, keys, buckets, policys etc will not be deleted
		'''

		self.instance_price_per_hour = 0
		if instance_location == 'cheapest':
			# Find cheapest location for the instance type
			print('Finding cheapest {spot}instance location. This can take several minutes.'.format(spot='spot ' if use_spot_instance else ''))
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

		if use_spot_instance and not instance_zone:
			# Instance zone was not given. Search cheapest one
			locinfo = CheapestSpotZone(instancetype,regions_to_check=[instance_location])
			instance_zone = locinfo['zone'][0]
			self.instance_price_per_hour = locinfo['price']

			if not max_hourly_price:
				max_hourly_price = locinfo['price']*3
				print('Setting spot instance max price to 3x the current price: {usd}'.format(usd=max_hourly_price))

		if jupyterfile:
			# We are running jupyter file

			if not usercommand:
				# Usercommand was not given, create it automatically
				# At some point '--save-on-error' flag should be added. See https://github.com/jupyter/nbconvert/issues/626
				result_files.append(console_output_filename)
				usercommand = '''
				jupyter nbconvert --ExecutePreprocessor.timeout={terminate_after_seconds} --to notebook --execute {jupyterfile} --output {jupyterfile}.result.ipynb >>{console_output_filename} 2>&1
				'''.format(
					jupyterfile=jupyterfile,
					terminate_after_seconds=terminate_after_seconds,
					console_output_filename=console_output_filename)

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
		self.image_name = image_name
		self.tags = tags
		self.instance_zone = instance_zone
		self.delete_bucket = delete_bucket
		self.delete_key = delete_key
		self.delete_iam_role = delete_iam_role
		self.delete_iam_policy = delete_iam_policy
		self.delete_iam_instance_profile = delete_iam_instance_profile
		self.unsafe_bucket_delete = unsafe_bucket_delete
		self.perform_cleanup = perform_cleanup
		self.console_output_filename = console_output_filename

		self.instance = None
		self.iam_policy = None
		self.spot_request_id = None
		self.instance_terminate_time = None
		self.instance_start_time = None
		self.start_time = None #time when start was called
		self.finish_time = None #time when call to start ended

		if not self.bucket_location:
			# If no bucket location is given, use same location as instance
			self.bucket_location = self.instance_location

		if not self.bucket_name:
			self.bucket_name = self._generate_uuid_name()

		if not self.keyname:
			self.keyname = self._generate_uuid_name()
		
		if not self.iam_role_name:
			self.iam_role_name = self._generate_uuid_name()

		if not self.iam_policy_name:
			self.iam_policy_name = self._generate_uuid_name()
		
		if not self.iam_instance_profile_name:
			self.iam_instance_profile_name = self._generate_uuid_name()

	def _generate_uuid_name(self):
		return self._get_main_tag() + uuid.uuid4().hex

	def _get_main_tag(self):
		if isinstance(self.tags, str):
			return self.tags
		elif not self.tags:
			return "quickaws-"
		else:
			return self.tags[0]

	def _tar_files(self):
		# Tar data

		tar = tarfile.open(self.tarname, "w:gz")
		for f in self.files_to_upload:
			if os.path.isfile(f) or os.path.isdir(f):
				tar.add(f)
			else:
				raise FileNotFoundError('File not found for tarring',f)
		tar.close()

	def _upload_to_s3(self):
		# Upload data to aws

		s3 = boto3.client('s3',region_name=self.bucket_location)
		try:
			s3.create_bucket(Bucket=self.bucket_name,
								CreateBucketConfiguration={'LocationConstraint': self.bucket_location})
			print('Created bucket {bucket}'.format(bucket=self.bucket_name))

			if self.delete_bucket is None:
				# We created new bucket, it should be automatically deleted
				self.delete_bucket = True
		except Exception as e:
			#Bucket probably already exists
			print(e)
			pass

		s3.upload_file(self.tarname, self.bucket_name, self.tarname)

	def _create_keys(self):
		# Create aws instance keys
		ec2 = boto3.client('ec2', region_name=self.instance_location)

		# Create keys for accessing the server, if key not present
		if not os.path.isfile(self.keyfilename):
			outfile = open(self.keyfilename,'w')
			key_pair = ec2.create_key_pair(KeyName=self.keyname)
			key_pair_out = str(key_pair['KeyMaterial'])
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

				if self.delete_key is None:
					# Delete automatically created key
					self.delete_key = True
			except ec2.exceptions.ClientError as e:
				if e.response['Error']['Code'] == 'InvalidKeyPair.Duplicate':
					# Already exist, all fine
					print('Key pair with name {name} already exist. Using it'.format(name=self.keyname))
				else:
					raise e
			

	def _anaconda_install_string(self):
		anaconda_install_string = ''
		if self.install_anaconda:
			anaconda_install_string = '''
				wget https://repo.anaconda.com/archive/{installed_anaconda_version}.sh -O ~/anaconda.sh  >> {cfname} 2>&1
				bash ~/anaconda.sh -b -p $HOME/anaconda >> {cfname} 2>&1
				'''.format(installed_anaconda_version=self.installed_anaconda_version,cfname=self.console_output_filename)
		return anaconda_install_string

	def _anaconda_update_string(self):
		anaconda_update_string = ''
		if self.update_anaconda:
			anaconda_update_string = '''
				conda update --yes -n root conda >> {cfname} 2>&1
				conda update --yes --all >> {cfname} 2>&1
				'''.format(cfname=self.console_output_filename)
		return anaconda_update_string

	def _shutdown_string(self):
		shutdown_string = 'sudo shutdown -h now'
		if self.do_not_shutdown:
			shutdown_string = ''
		return shutdown_string

	def _user_data_string(self):
		anaconda_install_string = self._anaconda_install_string()
		anaconda_update_string = self._anaconda_update_string()
		shutdown_string = self._shutdown_string()

		user_data = '''#!/bin/bash
		cd /root # set working directory
		sleep {terminate_after_seconds} && sudo shutdown -h now &
		pip install --upgrade botocore awscli >> {cfname} 2>&1 # some AMI versions have broken awscli which this will  fix
		aws s3 cp s3://{bucket_name}/{tarname} .  >> {cfname} 2>&1
		tar -zxvf {tarname}  >> {cfname} 2>&1
		{anaconda_install_string}
		export PATH="/root/anaconda/bin:$PATH" #required for custom ami/installation
		export PATH="/opt/conda/bin:$PATH" #required for normal anaconda image
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
									shutdown_string=shutdown_string,
									terminate_after_seconds=self.terminate_after_seconds,
									cfname=self.console_output_filename)
		return user_data

	def _create_spot_instance(self):
		user_data = self._user_data_string()

		ec2 = boto3.client('ec2', region_name=self.instance_location)
		spot_reqs = ec2.request_spot_instances(
			SpotPrice=str(self.max_hourly_price),
			LaunchSpecification={
				'ImageId':self._search_ami(),
				'InstanceType':self.instancetype,
				'Placement':{'AvailabilityZone':self.instance_zone},
				'KeyName':self.keyname,
				'UserData':base64.b64encode(user_data.encode("utf-8")).decode("utf-8") ,
				},
			InstanceCount=1,
			)

		self.spot_request_id = spot_reqs['SpotInstanceRequests'][0]['SpotInstanceRequestId']

		print('Created spot request {id}'.format(id=self.spot_request_id))

	def _wait_for_spot_instance(self):
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

	def _create_instance(self):
		# Create actual instance
		user_data = self._user_data_string()

		ec2 = boto3.resource('ec2', region_name=self.instance_location)

		instances = ec2.create_instances(
			ImageId=self._search_ami(),
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

	def _create_instance_permissions(self):
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

			self.iam_policy = iam.create_policy(
							PolicyName=self.iam_policy_name,
							PolicyDocument=policy,
							Description='quickaws')
			print('Created policy {iam_policy_name}'.format(iam_policy_name=self.iam_policy_name))
			if self.delete_iam_policy is None:
				self.delete_iam_policy = True

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

			if self.delete_iam_role is None:
				self.delete_iam_role = True

			iam_client = boto3.client('iam')
			iam_client.attach_role_policy(RoleName=self.iam_role_name,
								PolicyArn=self.iam_policy.arn)
			print('Attached policy {0} to role {1}'.format(self.iam_policy_name, self.iam_role_name))

			iam_client.create_instance_profile(InstanceProfileName=self.iam_instance_profile_name)
			print('Created instance profile {0}'.format(self.iam_instance_profile_name))

			iam_client.add_role_to_instance_profile(InstanceProfileName=self.iam_instance_profile_name,
												RoleName=self.iam_role_name)
			print('Added role {0} ro instance profile {1}'.format(self.iam_role_name, self.iam_instance_profile_name))

			if self.delete_iam_instance_profile is None:
				self.delete_iam_instance_profile = True
		

	def _associate_instance_profile(self):
		# Wait until instance is running
		print('Waiting for instance to enter ''running'' state')
		self.instance.wait_until_running()
		print('Instance entered ''running'' state')

		iam = boto3.resource('iam')
		instance_profile = iam.InstanceProfile(self.iam_instance_profile_name)
		
		ec2_client = boto3.client('ec2', region_name=self.instance_location)
		ec2_client.associate_iam_instance_profile(
			IamInstanceProfile={
				'Arn': instance_profile.arn,
				'Name': instance_profile.name
			},
			InstanceId=self.instance.id)
		print('Associated instance profile {0} with ec2 instance {1}'.format(self.iam_instance_profile_name, self.instance.id))

	def _print_log(self, chars_printed):
		ec2 = boto3.client('ec2')
		try:
			log = self.instance.console_output()
		except ec2.exceptions.ClientError as e:
			if e.response['Error']['Code'] == 'EndpointConnectionError':
				print('Connection error to AWS API')
				return chars_printed
			else:
				raise e
		if 'Output' in log:
			logstr = log['Output']
			newstr = logstr[chars_printed:-1]
			if len(newstr):
				print(newstr)
			chars_printed = len(logstr)
		return chars_printed

	def _wait_until_terminated(self):
		# Wait until instance is terminated
		print('Waiting for instance to terminate')
		chars_printed = 0
		while self.instance.state['Name'] != 'terminated':
			chars_printed = self._print_log(chars_printed)

		self.instance.wait_until_terminated()
		self.instance_terminate_time = datetime.datetime.now(pytz.utc)

		# Print rest of the log
		self._print_log(chars_printed)

		print('Instance terminated')

	def _download_from_s3(self):
		# Download results from aws

		print('Downloading results from S3')
		s3 = boto3.client('s3')
		try:
			s3.download_file(self.bucket_name, self.result_tarname, self.result_tarname)
			print('Files downloaded')
		except s3.exceptions.ClientError as e:
			if e.response['Error']['Code'] == '404':
				print('No files were uploaded back to s3.')
				return
			else:
				raise e

		# Extract downloaded data
		print('Extracting files')
		tar = tarfile.open(self.result_tarname,'r')
		tar.extractall()
		tar.close()

	def _search_ami(self):
		if self.instance_image_id:
			return self.instance_image_id
		if self.image_description or self.image_name:
			ec2 = boto3.resource("ec2", region_name=self.instance_location)
			filters = [ {
				'Name': 'description',
				'Values': [self.image_description]
			},
			{
				'Name': 'name',
				'Values': [self.image_name]
			},
			]
			images = ec2.images.filter(Filters=filters)
			
			latest = None
			for i in images:
				if not latest:
					latest = i
				elif parser.parse(i.creation_date) > parser.parse(latest.creation_date):
					latest = i
			print('Found ami {id} with description: {desc}'.format(id=latest.image_id,desc=latest.description))
			return latest.image_id

	def _record_instance_start_time(self):
		self.instance_start_time = self.instance.launch_time

	def _estimate_price(self):
		time_running = (self.instance_terminate_time - self.instance_start_time).total_seconds()
		total_time = (self.finish_time - self.start_time).total_seconds()
		total_price_time = max(total_time,60) #Minimum instance billing is for 60 seconds
		price = self.instance_price_per_hour
		cost_usd = total_price_time/60/60*price
		print('Running of instance for {seconds:0.0f}s cost approximately {cost:0.5f}USD'.format(seconds=time_running,cost=cost_usd))
		print('Total run time including setup {seconds:0.0f}'.format(seconds=total_time))

	def _remove_role_from_instance_profile(self):
		print('Removing role {role} from instance profile {profile}'.format(role=self.iam_role_name, profile=self.iam_instance_profile_name))
		iam_client = boto3.client('iam')
		iam_client.remove_role_from_instance_profile(
			InstanceProfileName=self.iam_instance_profile_name,
			RoleName=self.iam_role_name
			)

	def _cleanup(self):
		iam_client = boto3.client('iam')
		role_removed = False
		if self.delete_iam_instance_profile:
			self._remove_role_from_instance_profile()
			role_removed = True

			print('Deleting iam instance profile {profile}'.format(profile=self.iam_instance_profile_name))

			iam_client.delete_instance_profile(InstanceProfileName=self.iam_instance_profile_name)
		if self.delete_iam_policy:
			print('Detaching role {role} from iam policy {policy}'.format(role=self.iam_role_name,policy=self.iam_policy_name))

			iam_client.detach_role_policy(
				RoleName=self.iam_role_name,
				PolicyArn=self.iam_policy.arn
			)

			print('Deleting iam policy {policy}'.format(policy=self.iam_policy_name))

			iam_client.delete_policy(
				PolicyArn=self.iam_policy.arn
				)
		if self.delete_iam_role:
			if not role_removed:
				self._remove_role_from_instance_profile()

			print('Deleting iam role {role}'.format(role=self.iam_role_name))

			iam_client.delete_role(RoleName=self.iam_role_name)
		if self.delete_bucket:
			# Bucket can be deleted only if it is empty
			s3_resource = boto3.resource('s3')
			if self.unsafe_bucket_delete:
				print('Deleting all objects from bucket {bucket}'.format(bucket=self.bucket_name))
				bucket = s3_resource.Bucket(self.bucket_name)
				bucket.objects.all().delete()
			else:
				print('Deleting objects {f1} and {f2} from bucket {bucket}'.format(f1=self.tarname,f2=self.result_tarname,bucket=self.bucket_name))
				s3_resource.Object(self.bucket_name, self.tarname).delete()
				s3_resource.Object(self.bucket_name, self.result_tarname).delete()

			print('Deleting bucket {bucket}'.format(bucket=self.bucket_name))
			s3_client = boto3.client('s3')
			s3_client.delete_bucket(Bucket=self.bucket_name)
		if self.delete_key:
			print('Deleting key {key}'.format(key=self.keyname))
			
			ec2_client = boto3.client('ec2', region_name=self.instance_location)
			ec2_client.delete_key_pair(KeyName=self.keyname)
		
	def _log_public_ip(self):
		print('Instance public ip: {ip}'.format(ip=self.instance.public_ip_address))
		

	def start(self):
		self.start_time = datetime.datetime.now(pytz.utc)

		if not self.do_not_upload:
			self._tar_files()
			self._upload_to_s3()
		self._create_keys()

		self._create_instance_permissions()
		if self.use_spot_instance:
			self._create_spot_instance()
			self._wait_for_spot_instance()
		else:
			self._create_instance()
		self._record_instance_start_time()
		self._associate_instance_profile()
		self._log_public_ip()
		self._wait_until_terminated()
		self.finish_time = datetime.datetime.now(pytz.utc)
		self._download_from_s3()
		self._estimate_price()
		if self.perform_cleanup:
			self._cleanup()
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

def CheapestSpotZone(type='t2.micro',regions_to_check=[]):
	#Cheapest region
	min_price = math.inf
	min_region = []
	min_zone = []

	# All zones
	all_zones = []

	if not regions_to_check:
		# Search price for every region
		client = boto3.client('ec2',region_name='us-east-1')
		response = client.describe_regions()
		for reg in response['Regions']:
			regions_to_check.append(reg['RegionName'])
	for regname in regions_to_check:

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
	
