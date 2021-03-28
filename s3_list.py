""" List S3 bucket names for single region or all regions

Jaye Hicks Consulting, 2018
 **********************************************************************
 * Obligatory legal disclaimer:                                       *
 *  You are free to use this source code (this file and all other     *
 *  files referenced in this file) "AS IS" WITHOUT WARRANTY OF ANY    *
 *  KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, *
 *  THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A       *
 *  PARTICULAR PURPOSE. THE ENTIRE RISK AS TO THE QUALITY AND         *
 *  PERFORMANCE OF THIS SOURCE CODE IS WITH YOU.  SHOULD THE SOURCE   *
 *  CODE PROVE DEFECTIVE, YOU ASSUME THE COST OF ALL NECESSARY        *
 *  SERVICING, REPAIR OR CORRECTION. See the GNU GENERAL PUBLIC       *
 *  LICENSE Version 3, 29 June 2007 for more details.                 *
 **********************************************************************

List the S3 buckets for the region specified by the region argument.
To list S3 buckets across all regions provide a string that isn't a 
valid identifier for an AWS region (e.g., 'all').  Script will only 
work for standard regions (e.g., 'us-east-1'); will not work for 
'aws-cn' or 'aws-gov'.  

If properly formatted arguments are supplied for access key id and
secret access key arguments, they will be used to establish a custom 
boto3 session object based on those credentials vs. the credentials of
the default profile located in ".aws/credentials" file.  If the AWS
credentials are improperly formatted or otherwise invalid, the 
credentials of  the default profile located in ".aws/credentials" file 
will be used.  

If a custom boto3 session is established, the endpoint parameter will
be used to specify which AWS regional endpoint you want to go through 
when accessing AWS service APIs. It will default to 'us-east-1'.   

Args:
  region (str):  Required.  AWS region (e.g., 'us-east-1'). Any string
                 other than a valid standard region identifier, list 
                 buckets across all standard regions
  id (str):      Optional. AWS access key id to use for authorization
  secret(str):   Optional. AWS secret access key to use for auth
  endpoint(str): Optional. Regional endpoint to use for AWS API calls
  
Returns:
  (str): list of S3 bucket names or 'no buckets were located'
  
Usage:
  'python s3_list.py all'
  'python s3_list.py us-east-1 -i 12345678901234567890 
    -s 1234567890123456789012345678901234567890 -e us-east-1'
  
  '>>> import s3_list'
  '>>> s3_list.s3_list("all")'
  '>>> s3_list.s3_list("us-east-1", id="12345678901234567890",
         secret="1234567890123456789012345678901234567890", 
         endpoint="us-east-1")'  

Dependencies:
  argparse
  logging
  re
  boto3
"""
import argparse
import logging
import re
import boto3

custom_session = None
__all__        = ['s3_list', 'validate_region']
logging.basicConfig(filename='s3_list.log',level=logging.INFO)


def validate_region(input_region):
  """ If arg not AWS standard region retun '' otherwise return 
  the arg passed in, in lower case.  
  """
  region = ''
  if(isinstance(input_region, str)):
    region = input_region.lower()
    if(not region in boto3.Session().get_available_regions('s3')):
      region = ''
  return(region)


def _create_custom_session(id, key, endpoint):
  """ Attempt to create a custom boto3 session to overide use of the 
  default profile in the ".aws/credentials" file.  
  
  Not a public function.  All arguments passed in are of type str
  """
  global custom_session
  custom_session = None
  if(id.isalnum and (len(id)  == 20)):
    if(re.match(r'^[A-Za-z0-9/+]*$', key) and (len(key) == 40)):
      region = validate_region(endpoint)
      if(not region):
        region = 'us-east-1'
      try:
        custom_session = boto3.Session(aws_access_key_id= id, 
                                       aws_secret_access_key= key,
                                       region_name= region) 
      except Exception as e:
        custom_session = None
        logging.error(f'Boto3 exception thrown: {e}')  
         
  
def s3_list(region, id='', secret='', endpoint=''):
  """ Return list of S3 buckets for specified region.  If arg not a
  valid region identifier return list of s3 buckets across all regions.
  
  As of 1/18 AWS API inconsistent behavior. 's3.get_bucket_location()'
  returns 'None' as a bucket's LocationConstraint for any bucket
  residing in us-east-1, instead of the bucket's location.
        
  Args:
    region (str):  Required. Any string other than a valid standard
                   region results in listing buckets for all regions
    id (str):      Optional. AWS access key id to use for authorization
    secret(str):   Optional. AWS secret access key to use for auth
    endpoint(str): Optional. Regional endpoint to use for AWS API calls
    
  Returns:
    (str): either S3 bucket names or 'no buckets were located'
  """
  global custom_session
  bucket_list = ''
  region      = validate_region(region)
  
  if(isinstance(id, str) and isinstance(secret, str)):
    if(id and secret):
      _create_custom_session(id, secret, endpoint)
  
  if(region):
    try:
      if(custom_session is None):       
        s3_access = boto3.client('s3')
      else:
        s3_access = custom_session.client('s3')
      for bucket in s3_access.list_buckets()['Buckets']:
        loc_constraint = s3_access.get_bucket_location(
                           Bucket = bucket['Name'])['LocationConstraint']
        if ((region == 'us-east-1') and ((loc_constraint is None) or 
            (loc_constraint == 'us-east-1'))): # AWS API inconsistency
          bucket_list += bucket['Name'] + ', '
        elif (region == loc_constraint):
          bucket_list += bucket['Name'] + ', '
    except Exception as e:
      logging.error(f'Boto3 exception thrown: {e}')    
  else:
    try:
      if(custom_session is None):
        s3_access = boto3.resource('s3')
      else:
        s3_access = custom_session.resource('s3')
      for bucket in s3_access.buckets.all():
        bucket_list += bucket.name + ', '
    except Exception as e:
      logging.error(f'Boto3 exception thrown: {e}')

  if(bucket_list.endswith(', ')):
    bucket_list = bucket_list[:-2]

  if(not bucket_list):
    if(not region):
      bucket_list = 'No buckets exist in any region'
    else:
      bucket_list = f'No buckets exist in region: {region}'
  else:
    if(not region):
      bucket_list = f'S3 buckets across all regions: {bucket_list}'
    else:
      bucket_list = f'S3 buckets for region {region}: {bucket_list}'
      
  custom_session = None
      
  return(bucket_list)
  
  
if __name__ == '__main__':    
  parser = argparse.ArgumentParser(
    description = 'list S3 buckets for an AWS account')
  parser.add_argument('region', type=str, 
                      help='specify AWS region for bucket list; default is all regions')
  parser.add_argument('-i', '--id', type=str,
                      help='specify access key id to authorize access')
  parser.add_argument('-s', '--secret', type=str,
                      help='specify secret access key to authorize access')
  parser.add_argument('-e', '--endpoint', type=str,
                      help='specify which AWS regional endpoint to use')
  args = parser.parse_args() 
  
  convert_None = lambda arg: '' if arg is None else arg 
  
  print(s3_list(args.region, convert_None(args.id), convert_None(args.secret),
                convert_None(args.endpoint)))
