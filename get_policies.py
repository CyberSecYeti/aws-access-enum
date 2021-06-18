import boto3, json
import fnmatch, pickle
def getpolicies():

    istruncated = True

    client = boto3.client('iam')
    awsMarker = ''
    policylist = []
    while istruncated:
        if len(awsMarker):
            response = client.get_account_authorization_details(Filter=['AWSManagedPolicy','LocalManagedPolicy'],Marker=awsMarker)
        else:
            response = client.get_account_authorization_details(Filter=['AWSManagedPolicy','LocalManagedPolicy'])
        
        if 'Marker' in response:
            awsMarker=response['Marker']
        istruncated=response['IsTruncated']

        for policy in response['Policies']:
            for policygroup in policy['PolicyVersionList']:
                if(policygroup['IsDefaultVersion']):
                    #print(policygroup)
                    statementblock = []
                    if isinstance(policygroup['Document']['Statement'],list):
                        statementblock = policygroup['Document']['Statement']
                    else:
                        statementblock = [policygroup['Document']['Statement']]
                    for statement in statementblock:
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
                        #print(statement)
                        #print(statement[boolresource])
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
                                            'PolicyType':'Standalone',
                                            'Resource':resource,
                                            'ResourceNegate':ResourceNegate,
                                            'Action':action,
                                            'ActionNegate':ActionNegate,
                                            'ResourceAction':resourceaction[0],
                                            'Effect':statement['Effect'],
                                            'Condition':condition,
                                            'PolicyName' : policy['PolicyName'],
                                            'PolicyId' : policy['PolicyId'],
                                            'PolicyArn' : policy['Arn'],
                                            'Path':policy['Path']
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
                                        'PolicyType':'Standalone',
                                        'Resource':resource,
                                        'ResourceNegate':ResourceNegate,
                                        'Action':action,
                                        'ActionNegate':ActionNegate,
                                        'ResourceAction':resourceaction[0],
                                        'Effect':statement['Effect'],
                                        'Condition':condition,
                                        'PolicyName' : policy['PolicyName'],
                                        'PolicyId' : policy['PolicyId'],
                                        'PolicyArn' : policy['Arn'],
                                        'Path':policy['Path']
                                    }
                                    policylist.append(policyline)
                        else:
                            resource = statement[boolresource]
                            #print(statement)
                            if isinstance(statement[boolAction], dict) or isinstance(statement[boolAction], list):
                                for action in statement[boolAction]:
                                    resourceaction = action.split(":")
                                    if 'Condition' in statement.keys():
                                            condition = statement['Condition']
                                    else:
                                        condition = ''
                                    policyline = {
                                        'PolicyType':'Standalone',
                                        'Resource':resource,
                                        'ResourceNegate':ResourceNegate,
                                        'Action':action,
                                        'ActionNegate':ActionNegate,
                                        'ResourceAction':resourceaction[0],
                                        'Effect':statement['Effect'],
                                        'Condition':condition,
                                        'PolicyName' : policy['PolicyName'],
                                        'PolicyId' : policy['PolicyId'],
                                        'PolicyArn' : policy['Arn'],
                                        'Path':policy['Path']
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
                                    'PolicyType':'Standalone',
                                    'Resource':resource,
                                    'ResourceNegate':ResourceNegate,
                                    'Action':action,
                                    'ActionNegate':ActionNegate,
                                    'ResourceAction':resourceaction[0],
                                    'Effect':statement['Effect'],
                                    'Condition':condition,
                                    'PolicyName' : policy['PolicyName'],
                                    'PolicyId' : policy['PolicyId'],
                                    'PolicyArn' : policy['Arn'],
                                    'Path':policy['Path']
                                }
                                policylist.append(policyline)
                        
    pickle.dump(policylist, open('policies.p','wb'))

    #print(policylist)




            