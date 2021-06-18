import boto3, json
import fnmatch, pickle

def getgrouppolicies():
    istruncated = True

    client = boto3.client('iam')
    awsMarker = ''
    grouplist = []
    while istruncated:
        if len(awsMarker):
            response = client.get_account_authorization_details(Filter=['Group'],Marker=awsMarker)
        else:
            response = client.get_account_authorization_details(Filter=['Group'])
        if 'Marker' in response:
            awsMarker=response['Marker']
        istruncated=response['IsTruncated']

        for group in response['GroupDetailList']:
            policylist = []
            print(group['GroupName'])
            if('GroupPolicyList' in group):

                for policy in group['GroupPolicyList']:
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
                                            'PolicyType':'Group',
                                            'Resource':resource,
                                            'ResourceNegate':ResourceNegate,
                                            'Action':action,
                                            'ActionNegate':ActionNegate,
                                            'ResourceAction':resourceaction[0],
                                            'Effect':statement['Effect'],
                                            'Condition':condition,
                                            'PolicyName' : policy['PolicyName'],
                                            'PolicyArn' : group['Arn']
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
                                        'PolicyType':'Group',
                                        'Resource':resource,
                                        'ResourceNegate':ResourceNegate,
                                        'Action':action,
                                        'ActionNegate':ActionNegate,
                                        'ResourceAction':resourceaction[0],
                                        'Effect':statement['Effect'],
                                        'Condition':condition,
                                        'PolicyName' : policy['PolicyName'],
                                        'PolicyArn' : group['Arn']
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
                                        'PolicyType':'Group',
                                        'Resource':resource,
                                        'ResourceNegate':ResourceNegate,
                                        'Action':action,
                                        'ActionNegate':ActionNegate,
                                        'ResourceAction':resourceaction[0],
                                        'Effect':statement['Effect'],
                                        'Condition':condition,
                                        'PolicyName' : policy['PolicyName'],
                                        'PolicyArn' : group['Arn']
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
                                    'PolicyType':'Group',
                                    'Resource':resource,
                                    'ResourceNegate':ResourceNegate,
                                    'Action':action,
                                    'ActionNegate':ActionNegate,
                                    'ResourceAction':resourceaction[0],
                                    'Effect':statement['Effect'],
                                    'Condition':condition,
                                    'PolicyName' : policy['PolicyName'],
                                    'PolicyArn' : group['Arn']
                                }
                                policylist.append(policyline)
            groupline = {
                'PolicyType':'Group',
                'GroupName': group['GroupName'],
                'GroupId' : group['GroupId'],
                'GroupArn' : group['Arn'],
                'Path':group['Path'],
                'ManagedPolicies':group['AttachedManagedPolicies'],
                'LocalPolicies':policylist,
            }
            grouplist.append(groupline)
    pickle.dump(grouplist, open('grouplist.p','wb'))