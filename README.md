# quickaws
Python module / script for sending Jupyter notebooks (or other work) to cheapest AWS (spot) instance and getting analyzed data / results as fast and cheaply as possible. AWS instance is automatically terminated after the notebook has been analyzed even if network connection is interrupted.

# Usage examples

Run Jupyter notebook which does not require any input files and does not produce any output files on cheapest c5d.18xlarge spot instance.

```
import quickaws

aws = quickaws.QuickAws(jupyterfile='notebook.ipynb',
                        instancetype='c5d.large'
                        )
aws.start()

```

Output should be similar to

```
Finding cheapest spot instance location. This can take several minutes.
Cheapest c5d.large spot instance is located at us-east-2a with price 0.019USD/h
Cheapest on demand 0.096USD/h at ['us-east-1', 'us-east-2', 'us-west-2']
Created bucket quickaws471ed4539c26453a947ea2adae1ce539
Keyfile key.pem already exist, using existing key
Imported key pair quickaws55948ff836b141fb82a56aad446ccc36 from file key.pem
Created policy quickaws9192e1da0a9d408cbfec632c1c9597e8
Created role quickaws21ae3a1b515b47a3825bdb0ef13a82ad
Attached policy quickaws9192e1da0a9d408cbfec632c1c9597e8 to role quickaws21ae3a1b515b47a3825bdb0ef13a82ad
Created instance profile quickawsd75d05c042204f92957b216069611fcd
Added role quickaws21ae3a1b515b47a3825bdb0ef13a82ad ro instance profile quickawsd75d05c042204f92957b216069611fcd
Found ami ami-25695140 with description: Anaconda3 5.2.0 on Amazon Linux 20180608.1746
Created spot request sir-bapirmvg
Waiting for spot instance request to be fulfilled.
Spot instance fulfilled with instance i-0077e4abbcbca2468
Waiting for instance to enter running state
Instance entered running state
Associated instance profile quickawsd75d05c042204f92957b216069611fcd with ec2 instance i-0077e4abbcbca2468
Instance public ip: 52.14.11.37
Waiting for instance to terminate
Instance terminated
Downloading results from S3
Files downloaded
Extracting files
Running of instance for 73s cost approximately 0.00042USD
Total run time including setup 80
Removing role quickaws21ae3a1b515b47a3825bdb0ef13a82ad from instance profile quickawsd75d05c042204f92957b216069611fcd
Deleting iam instance profile quickawsd75d05c042204f92957b216069611fcd
Detaching role quickaws21ae3a1b515b47a3825bdb0ef13a82ad from iam policy quickaws9192e1da0a9d408cbfec632c1c9597e8
Deleting iam policy quickaws9192e1da0a9d408cbfec632c1c9597e8
Deleting iam role quickaws21ae3a1b515b47a3825bdb0ef13a82ad
Deleting objects data.tar.gz and result.tar.gz from bucket quickaws471ed4539c26453a947ea2adae1ce539
Deleting bucket quickaws471ed4539c26453a947ea2adae1ce539
Deleting key quickaws55948ff836b141fb82a56aad446ccc36
Finished
```

Results and notebook which has been run will be downloaded to working directory.
Note that first run can take quite long time to setup as gathering price information is extreamly slow. You can speed things up if you already know the location where you want to run the instance:

```
import quickaws

aws = quickaws.QuickAws(jupyterfile='notebook.ipynb',
                        instancetype='c5d.large',
                        instance_location='us-east-2a'
                        )
aws.start()

```

By default Anaconda3 5.2.0 image is used. Unfortunately this image does not support all instance types (for example c5d.18xlarge is not supported). You can change to other AMIs by setting 'image_description' and 'image_name' or by setting 'instance_image_id':

```
import quickaws

aws = quickaws.QuickAws(jupyterfile='notebook.ipynb',
                        instancetype='c5d.large',
                        instance_location='us-east-2a',
                        image_name='*Deep Learning AMI (Amazon Linux) Version*',
                        image_description='*'
                        )
aws.start()

```

# Dependencies

## awspricing 
It is highly recommended to set environmental variables AWSPRICING_USE_CACHE and AWSPRICING_CACHE_MINUTES. See https://github.com/lyft/awspricing