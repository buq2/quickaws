# Quick AWS module for fast execution of scripts at aws

import boto3
import tarfile
import os.path

class QuickAws(object):
	def __init__(self,
		files_to_upload = [],
		result_files = [],
		usercommand = '',
		tarname = 'data.tar.gz',
		result_tarname = 'result.tar.gz',
		bucket_name = 'buq2-ml-bucket',
		bucket_location = 'eu-central-1',
		instance_location = 'eu-central-1',
		keyfilename = 'key.pem',
		install_anaconda = False,
		installed_anaconda_version = 'Anaconda3-5.2.0-Linux-x86_64',
		update_anaconda = False,
		keyname = 'analysis-ec2-instance-key',
		instancetype = 't2.micro', #'c5.large'#'t2.micro'
		instance_image_id = 'ami-031723628dc6a197d', # 'ami-0f5dbc86dd9cbf7a8'=base, 'ami-031723628dc6a197d'=anaconda3-buq2
		iam_role_name = 'buq2-ml-bucket-access-role',
		iam_policy_name = 'buq2-ml-bucket-access-policy',
		iam_instance_profile_name = 'buq2-ml-bucket-access-profile',
		monitoring = False,
		jupyterfile = ''
		):

		if jupyterfile:
			if not usercommand:
				usercommand = 'jupyter nbconvert --to notebook --execute {jupyterfile} --output {jupyterfile}.result.ipynb'.format(jupyterfile=jupyterfile)

			result_files.append('{jupyterfile}.result.ipynb'.format(jupyterfile=jupyterfile))
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

		self.instance = None
		
	def _tarFiles(self):
		# Tar data
		
		tar = tarfile.open(self.tarname, "w:gz")
		for f in self.files_to_transfer:
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
		ec2 = boto3.resource('ec2', region_name=self.instance_location)

		# Create keys for accessing the server, if key not present
		if not os.path.isfile(self.keyfilename):
			outfile = open(self.keyfilename,'w')
			key_pair = ec2.create_key_pair(KeyName=self.keyname)
			key_pair_out = str(key_pair.key_material)
			outfile.write(key_pair_out)
			outfile.close()
		else:
			print('Keyfile {keyfilename} already exist, using existing key'.format(keyfilename=self.keyfilename)

	def _createInstance(self):
		# Create actual instance
		anaconda_install_string = ''
		if self.install_anaconda:
			anaconda_install_string = '''
				wget https://repo.anaconda.com/archive/{installed_anaconda_version}.sh -O ~/anaconda.sh
				bash ~/anaconda.sh -b -p $HOME/anaconda
				'''.format(installed_anaconda_version=self.installed_anaconda_version)

		anaconda_update_string = ''
		if self.update_anaconda:
			anaconda_update_string = '''
				conda update --yes -n root conda
				conda update --yes --all
				'''

		user_data = '''#!/bin/bash
		aws s3 cp s3://{bucket_name}/{tarname} .
		tar -zxvf {tarname}
		{anaconda_install_string}
		export PATH="$HOME/anaconda/bin:$PATH"
		{anaconda_update_string}
		{usercommand}
		tar cfz {result_tarname} {result_files}
		aws s3 cp {result_tarname} s3://{bucket_name}/{result_tarname}
		sudo shutdown -h now'''.format(bucket_name=self.bucket_name, 
									tarname=self.tarname, 
									result_tarname=self.result_tarname,
									result_files=' '.join(self.result_files),
									usercommand=self.usercommand,
									anaconda_update_string=anaconda_update_string,
									anaconda_install_string=anaconda_install_string)

		instances = ec2.create_instances(
			ImageId=self.instance_image_id, 
			MinCount=1, 
			MaxCount=1,
			KeyName=self.keyname,
			InstanceType=self.instancetype,
			Monitoring={'Enabled':self.monitoring},
			InstanceInitiatedShutdownBehavior='terminate',
			UserData=user_data
		)
		self.instance = instances[0]
		print("Created instance {0}".format(self.instance.id))

	def _createInstancePermissions(self):
		# Wait until instance is running
		self.instance.wait_until_running()

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
						"Resource": ["arn:aws:s3:::{0}"]
					}},
					{{
						"Effect": "Allow",
						"Action": [
							"s3:PutObject",
							"s3:GetObject"
						],
						"Resource": ["arn:aws:s3:::{1}/*"]
					}}
				]
			}}'''.format(bucket_name=self.bucket_name)

			policy_response = iam.create_policy(PolicyName=self.iam_policy_name,
							PolicyDocument=policy)
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
						AssumeRolePolicyDocument=role_policy)
			print('Created role {0}'.format(self.iam_role_name))

			iam_client = boto3.client('iam')
			iam_client.attach_role_policy(RoleName=self.iam_role_name,
								PolicyArn=policy_response.arn)
			print('Attached policy {0} to role {0}'.format(self.iam_policy_name, self.iam_role_name))
			
			iam_client.create_instance_profile(InstanceProfileName=self.iam_instance_profile_name)
			print('Created instance profile {0}'.format(self.iam_instance_profile_name))
			
			iam_client.add_role_to_instance_profile(InstanceProfileName=self.iam_instance_profile_name,
												RoleName=self.iam_role_name)
			print('Added role {0} ro instance profile {1}'.format(self.iam_role_name, self.iam_instance_profile_name))
			
			
		iam_client = boto3.client('iam')
		ec2_client = boto3.client('ec2', region_name=self.instance_location)
		ec2_client.associate_iam_instance_profile(
			IamInstanceProfile={
				'Arn': instance_profile.arn,
				'Name': instance_profile.name
			},
			InstanceId=self.instance.id)
		print('Associated instance profile {0} with ec2 instance {1}'.format(self.iam_instance_profile_name, self.instance.id))

	def _waitUntilTerminated(self):
		# Wait until instance is terminated
		chars_printed = 0
		while self.instance.state['Name'] != 'terminated':
		    log = self.instance.console_output()
		    if 'Output' in log:
		        logstr = log['Output']
		        print(logstr[chars_printed:-1])
		        chars_printed = len(logstr)
		
		self.instance.wait_until_terminated()
		print('Instance terminated')

	self _downloadFromS3(self):
		# Download results from aws
		s3 = boto3.client('s3')
		s3.download_file(self.bucket_name, self.result_tarname, self.result_tarname)
		
		# Extract downloaded data
		tar = tarfile.open(self.result_tarname,'r')
		tar.extractall()
		tar.close()

	def start(self):
		self._tarFiles()
		self._uploadToS3()
		self._createKeys()
		self._createInstance()
		self._createInstancePermissions()
		self._waitUntilTerminated()
		self._downloadFromS3()
