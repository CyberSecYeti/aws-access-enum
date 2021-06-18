# aws-access-enum

aws-access-enum is a Python script for identifying AWS IAM Users, Groups, and Roles with access to specific resources.

## Requirements

Python3 w/ boto3 module

awscli - uses default credential profile (must have "iam:Get\*" and "iam:List\*" permissions)


## Usage

Parse all IAM policy documents into *\.p files (CAUTION: These files will contain sensitive IAM policy information. Practice good OPSEC!!)
```bash
python3 getallpolicies.py
```

Search for Users, Groups, and Roles with access to a specific ARN
```bash
python3 searchARN.py <ARN>
```

## TODO
* Add flag to ignore Get/List permissions
* Fix Permissions Boundary identification
* Fix Deny logic

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License
[MIT](https://choosealicense.com/licenses/mit/)
