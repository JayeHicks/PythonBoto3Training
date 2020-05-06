# PythonBoto3Training
Two Python 3.x modules, that use Boto3, suitable for use in introductory / intermediate training

# Overview
I developed two Python 3.x modules suitable for use in introductory to intermediate level training.  Both use Boto3 to interact with the AWS S3 service.  

The module s3_list.py is suitable for short, entry-level training.  This module returns a list of the S3 buckets that belong to an AWS account.  I have found this module ideal for entry-level training sessions lasting a day or less.

The module S3_man.py is suitable for longer, intermediate-level training.  It imports (i.e., includes) the s3_list.py module and supports a few basic S3 operations (e.g., list the objects in a bucket, create a bucket, delete a bucket).

Both modules work across the “Boto3 Resource” and the “Boto3 Client” API sets.   Additionally, both can be run using the default profile contained in the “<some directory path>/.aws/credentials” file (i.e., created during installation of the AWS CLI) or using an IAM user of your choice.  To execute a module's functionality using an IAM user of your choice, you supply the AWS IAM access key id and the AWS IAM secret access key as parameters to  a function call or a command line operation.  If you do so, you also have the option of specifying which AWS regional endpoint will be used when communicating with the S3 service.

Outside of Boto3, both modules only make use of modules from the Python 3.x Standard Library.  And finally, both modules have the ability to be run as a stand-alone script or to be imported by another module.  

# License
This project is licensed under the GNU Public License v3.0.  For details see: https://github.com/JayeHicks/PythonBoto3Training/blob/master/LICENSE


