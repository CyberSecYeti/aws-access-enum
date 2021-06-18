import boto3, json
import fnmatch, pickle
def getrolepolicies():

    istruncated = True

    client = boto3.client('iam')
    awsMarker = ''
    rolelist = []
    while istruncated:
        if len(awsMarker):
            response = client.get_account_authorization_details(Filter=['Role'],Marker=awsMarker)
        else:
            response = client.get_account_authorization_details(Filter=['Role'])
        if 'Marker' in response:
            awsMarker=response['Marker']
        istruncated=response['IsTruncated']

        for role in response['RoleDetailList']:
            policylist = []
            print(role['Arn'])
            if('RolePolicyList' in role):

                for policy in role['RolePolicyList']:
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
                                            'PolicyType':'Role',
                                            'Resource':resource,
                                            'ResourceNegate':ResourceNegate,
                                            'Action':action,
                                            'ActionNegate':ActionNegate,
                                            'ResourceAction':resourceaction[0],
                                            'Effect':statement['Effect'],
                                            'Condition':condition,
                                            'PolicyName' : policy['PolicyName'],
                                            'PolicyArn' : role['Arn']
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
                                        'PolicyType':'Role',
                                        'Resource':resource,
                                        'ResourceNegate':ResourceNegate,
                                        'Action':action,
                                        'ActionNegate':ActionNegate,
                                        'ResourceAction':resourceaction[0],
                                        'Effect':statement['Effect'],
                                        'Condition':condition,
                                        'PolicyName' : policy['PolicyName'],
                                        'PolicyArn' : role['Arn']
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
                                        'PolicyType':'Role',
                                        'Resource':resource,
                                        'ResourceNegate':ResourceNegate,
                                        'Action':action,
                                        'ActionNegate':ActionNegate,
                                        'ResourceAction':resourceaction[0],
                                        'Effect':statement['Effect'],
                                        'Condition':condition,
                                        'PolicyName' : policy['PolicyName'],
                                        'PolicyArn' : role['Arn']
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
                                    'PolicyType':'Role',
                                    'Resource':resource,
                                    'ResourceNegate':ResourceNegate,
                                    'Action':action,
                                    'ActionNegate':ActionNegate,
                                    'ResourceAction':resourceaction[0],
                                    'Effect':statement['Effect'],
                                    'Condition':condition,
                                    'PolicyName' : policy['PolicyName'],
                                    'PolicyArn' : role['Arn']
                                }
                                policylist.append(policyline)
            if('PermissionsBoundary' in role):
                PermissionsBoundary = role['PermissionsBoundary']['PermissionsBoundaryArn']
            else:
                PermissionsBoundary = ''
            roleline = {
                'PolicyType':'Role',
                'Rolename': role['RoleName'],
                'RoleId' : role['RoleId'],
                'RoleArn' : role['Arn'],
                'Path':role['Path'],
                'ManagedPolicies':role['AttachedManagedPolicies'],
                'LocalPolicies':policylist,
                'PermissionsBoundary':PermissionsBoundary
            }
            rolelist.append(roleline)
    pickle.dump(rolelist, open('rolelist.p','wb'))