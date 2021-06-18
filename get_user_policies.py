import boto3, json
import fnmatch, pickle
def getuserpolicies():
    istruncated = True

    client = boto3.client('iam')
    awsMarker = ''
    userlist = []
    while istruncated:
        if len(awsMarker):
            response = client.get_account_authorization_details(Filter=['User'],Marker=awsMarker)
        else:
            response = client.get_account_authorization_details(Filter=['User'])
        if 'Marker' in response:
            awsMarker=response['Marker']
        istruncated=response['IsTruncated']

        for user in response['UserDetailList']:
            policylist = []
            print(user['UserName'])
            if('UserPolicyList' in user):

                for policy in user['UserPolicyList']:
                    policygroup = policy['PolicyDocument']
                    for statement in policygroup['Statement']:
                        if('NotResource' in statement):
                            boolresource='NotResource'
                            ResourceNegate = True
                        else:
                            boolresource='Resource'
                            ResourceNegate=False
                        if('NotAction' in statement):
                            boolAction='NotAction'
                            ActionNegate=True
                        else:
                            boolAction='Action'
                            ActionNegate=False
                        if isinstance(statement[boolresource], dict) or isinstance(statement[boolresource], list):
                            for resource in statement[boolresource]:
                                
                                if isinstance(statement[boolAction], dict) or isinstance(statement[boolAction], list):
                                    for action in statement[boolAction]:
                                        resourceaction = action.split(":")
                                        if 'Condition' in statement.keys():
                                            condition = statement['Condition']
                                        else:
                                            condition = ''

                                        policyline = {
                                            'PolicyType':'User',
                                            'Resource':resource,
                                            'ResourceNegate':ResourceNegate,
                                            'Action':action,
                                            'ActionNegate':ActionNegate,
                                            'ResourceAction':resourceaction[0],
                                            'Effect':statement['Effect'],
                                            'Condition':condition,
                                            'PolicyName' : policy['PolicyName'],
                                            'PolicyArn':user['Arn']
                                        }
                                        policylist.append(policyline)
                                else:
                                    action = statement[boolAction]
                                    resourceaction = statement[boolAction].split(":")
                                    if 'Condition' in statement.keys():
                                            condition = statement['Condition']
                                    else:
                                        condition = ''
                                    policyline = {
                                        'PolicyType':'User',
                                        'Resource':resource,
                                        'ResourceNegate':ResourceNegate,
                                        'Action':action,
                                        'ActionNegate':ActionNegate,
                                        'ResourceAction':resourceaction[0],
                                        'Effect':statement['Effect'],
                                        'Condition':condition,
                                        'PolicyName' : policy['PolicyName'],
                                        'PolicyArn':user['Arn']
                                    }
                                    policylist.append(policyline)
                        else:
                            resource = statement[boolresource]
                            if isinstance(statement[boolAction], dict) or isinstance(statement[boolAction], list):
                                for action in statement[boolAction]:
                                    resourceaction = action.split(":")
                                    if 'Condition' in statement.keys():
                                            condition = statement['Condition']
                                    else:
                                        condition = ''
                                    policyline = {
                                        'PolicyType':'User',
                                        'Resource':resource,
                                        'ResourceNegate':ResourceNegate,
                                        'Action':action,
                                        'ActionNegate':ActionNegate,
                                        'ResourceAction':resourceaction[0],
                                        'Effect':statement['Effect'],
                                        'Condition':condition,
                                        'PolicyName' : policy['PolicyName'],
                                        'PolicyArn':user['Arn']
                                    }
                                    policylist.append(policyline)
                            else:
                                action = statement[boolAction]
                                resourceaction = action.split(":")
                                if 'Condition' in statement.keys():
                                            condition = statement['Condition']
                                else:
                                    condition = ''
                                policyline = {
                                    'PolicyType':'User',
                                    'Resource':resource,
                                    'ResourceNegate':ResourceNegate,
                                    'Action':action,
                                    'ActionNegate':ActionNegate,
                                    'ResourceAction':resourceaction[0],
                                    'Effect':statement['Effect'],
                                    'Condition':condition,
                                    'PolicyName' : policy['PolicyName'],
                                    'PolicyArn':user['Arn']
                                }
                                policylist.append(policyline)
            if('PermissionsBoundary' in user):
                PermissionsBoundary = user['PermissionsBoundary']['PermissionsBoundaryArn']
            else:
                PermissionsBoundary = ''
            userline = {
                'PolicyType':'User',
                'Username': user['UserName'],
                'UserId' : user['UserId'],
                'UserArn' : user['Arn'],
                'Path':user['Path'],
                'ManagedPolicies':user['AttachedManagedPolicies'],
                'Groups':user['GroupList'],
                'LocalPolicies':policylist,
                'PermissionsBoundary':PermissionsBoundary
            }
            userlist.append(userline)
    pickle.dump(userlist, open('userlist.p','wb'))