import json, pickle, fnmatch,sys
import jsonmerge


def findpolicymatch(searchpolicy, searchARN):
    if(fnmatch.fnmatch(searchResourceType,searchpolicy['ResourceAction'])) :
        if(searchpolicy['ResourceNegate']):
            if(fnmatch.fnmatch(searchARN,searchpolicy['Resource']) == False):
                if(searchpolicy['PolicyArn'] not in policymatch):
                    policymatch.append(searchpolicy['PolicyArn'])
                if(searchpolicy['ActionNegate']):
                    policyline = {
                        'PolicyType':searchpolicy['PolicyType'],
                        'Arn':searchpolicy['PolicyArn'],
                        'PolicyDetails': {'Effect':searchpolicy['Effect'] , 'PolicyName': searchpolicy['PolicyName'] ,'NotResource': searchpolicy['Resource'] , 'NotAction': searchpolicy['Action'] ,'Condition':searchpolicy['Condition']}
                    }
                else:
                    policyline = {
                        'PolicyType':searchpolicy['PolicyType'],
                        'Arn':searchpolicy['PolicyArn'],
                        'PolicyDetails': {'Effect':searchpolicy['Effect'] , 'PolicyName': searchpolicy['PolicyName'] ,'NotResource': searchpolicy['Resource'] , 'Action': searchpolicy['Action'] ,'Condition':searchpolicy['Condition']}
                        #searchpolicy['Effect'] + ' ' + searchpolicy['PolicyName'] + ' ' + searchpolicy['Resource'] + '(NEGATED) ' + searchpolicy['Action'] + ' ' + json.dumps(searchpolicy['Condition'])
                    }
                policyActionmatch.append(policyline)
        else:
            if(fnmatch.fnmatch(searchARN,searchpolicy['Resource'])):
                if(searchpolicy['PolicyArn'] not in policymatch):
                    policymatch.append(searchpolicy['PolicyArn'])
                if(searchpolicy['ActionNegate']):
                    policyline = {
                        'PolicyType':searchpolicy['PolicyType'],
                        'Arn':searchpolicy['PolicyArn'],
                        'PolicyDetails': {'Effect':searchpolicy['Effect'] , 'PolicyName': searchpolicy['PolicyName'] ,'Resource': searchpolicy['Resource'] , 'NotAction': searchpolicy['Action'] ,'Condition':searchpolicy['Condition']}
                        #searchpolicy['Effect'] + ' ' + searchpolicy['PolicyName'] + ' ' + searchpolicy['Resource'] + ' ' + searchpolicy['Action'] + '(NEGATE)' + ' ' + json.dumps(searchpolicy['Condition'])
                    }
                else:
                    policyline = {
                        'PolicyType':searchpolicy['PolicyType'],
                        'Arn':searchpolicy['PolicyArn'],
                        'PolicyDetails': {'Effect':searchpolicy['Effect'] , 'PolicyName': searchpolicy['PolicyName'] ,'Resource': searchpolicy['Resource'] , 'Action': searchpolicy['Action'] ,'Condition':searchpolicy['Condition']}
                        #searchpolicy['Effect'] + ' ' + searchpolicy['PolicyName'] + ' ' + searchpolicy['Resource'] + ' ' + searchpolicy['Action']  + ' ' + json.dumps(searchpolicy['Condition'])
                    }
                policyActionmatch.append(policyline)

standalonepolicylist = pickle.load( open('policies.p','rb'))
userlist = pickle.load( open('userlist.p','rb'))
grouplist = pickle.load( open('grouplist.p','rb'))
rolelist = pickle.load( open('rolelist.p','rb'))

policylist = standalonepolicylist + userlist + grouplist + rolelist

policymatch = []
policyActionmatch = []

searchARN = sys.argv[1]
searchARNparts = searchARN.split(":",5)
searchResourceType= searchARNparts[2]
if( searchResourceType == 's3'):
    if('/' in searchARNparts[5]):
        searchResource = searchARNparts[5].split("/",1)[0]
    else:
        searchResource = searchARNparts[5]
    print(searchResource)

if(1==2):
    searchRegion = searchARNparts[3]
    #if len(searchARNparts[4]):
    searchAccount = searchARNparts[4]
    if('/' in searchARNparts[5]):
        searchResource = searchARNparts[5].split("/",1)
    elif(':' in searchARNparts[5]):
        print('')

for policyitem in policylist:
    searchpolicy = []
    #print(policyitem['PolicyType'])
    if(policyitem['PolicyType'] == 'Standalone'):
        
        findpolicymatch(policyitem, searchARN)
    else:   #(policyitem['PolicyType'] == 'User'):
        if(policyitem['LocalPolicies'] == []):
            continue
        for searchpolicy in policyitem['LocalPolicies']:
            findpolicymatch(searchpolicy, searchARN)



usermatch = False
userpolicymatch = []
for user in userlist:
    
    for manpolicy in user['ManagedPolicies']:
        if(manpolicy['PolicyArn'] in policymatch):
            newpolicy = True
            if user['Username'] in userpolicymatch:
                for policy in userpolicymatch:
                    if(policy['User'] == user['Username']):
                        newpolicy = False
                        userpolicymatch.remove(policy)
                    policy['PolicyMatch'].append(upolicy['PolicyArn'])
                    userpolicymatch.append(policy)
            if(newpolicy):
                userpolicymatch.append({'User' : user['Username'] , 'PolicyMatch' : [manpolicy['PolicyArn']]})
            usermatch = True
    for ugroup in user['Groups']:
        for group in grouplist:
            if(ugroup == group['GroupName']):
                for grouppolicy in group['ManagedPolicies']:
                    if(grouppolicy['PolicyArn'] in policymatch):
                        usermatch = True
                        userpolicymatch.append({'User' : user['Username'] , 'Group': ugroup , 'PolicyMatch' : [grouppolicy['PolicyArn']]})
                    #print(grouppolicy)
    for upolicy in policyActionmatch:       
        if(upolicy['PolicyType'] == 'User' and upolicy['Arn'] == user['UserArn']):
            usermatch = True
            newpolicy = True
            
            for policy in userpolicymatch:
                if(policy['User'] == user['Username']):
                    newpolicy = False
                    userpolicymatch.remove(policy)
                    policy['PolicyMatch'].append(upolicy['PolicyDetails'])
                    userpolicymatch.append(policy)
            if(newpolicy):
                userpolicymatch.append({'User' : user['Username'] , 'PolicyMatch' : [upolicy['PolicyDetails']]})



rolepolicymatch = []
rolematch = False
for role in rolelist:
    
    
    for manpolicy in role['ManagedPolicies']:
        if(manpolicy['PolicyArn'] in policymatch):
            newpolicy = True
            rolematch = True
            for policy in rolepolicymatch:
                if(policy['Role'] == role['Rolename']):
                    newpolicy = False
                    rolepolicymatch.remove(policy)
                    policy['PolicyMatch'].append(manpolicy['PolicyArn'])
                    rolepolicymatch.append(policy)
            if(newpolicy):
                rolepolicymatch.append({'Role' :role['Rolename'], 'PolicyMatch' : [manpolicy['PolicyArn']]})
            
    
    for upolicy in policyActionmatch:       
        if(upolicy['PolicyType'] == 'Role' and upolicy['Arn'] == role['RoleArn']):
            rolematch = True
            newpolicy = True
            
            for policy in rolepolicymatch:
                if(policy['Role'] == role['Rolename']):
                    newpolicy = False
                    rolepolicymatch.remove(policy)
                    policy['PolicyMatch'].append(upolicy['PolicyDetails'])
                    rolepolicymatch.append(policy)
            if(newpolicy):
                rolepolicymatch.append({'Role' :role['Rolename'], 'PolicyMatch' : [upolicy['PolicyDetails']]})
            #rolepolicymatch.append('Role ' + role['Rolename'] + ' ' + upolicy['PolicyDetails'])



groupmatch = False
grouppolicymatch = []

for group in grouplist:
   
    for manpolicy in group['ManagedPolicies']:
        if(manpolicy['PolicyArn'] in policymatch):
            grouppolicymatch.append({'Group' : group['GroupName'] , 'PolicyMatch' : [manpolicy['PolicyArn']]})
            groupmatch = True
    
    for upolicy in policyActionmatch:       
        if(upolicy['PolicyType'] == 'Group ' and upolicy['Arn'] == group['GroupArn']):
            groupmatch = True
            grouppolicymatch.append({'Group' : group['GroupName'] , 'PolicyMatch' : [upolicy['PolicyDetails']]})

#if(usermatch):
    #print({'Users':userpolicymatch})

#if(groupmatch):
#    print(grouppolicymatch)
#if(rolematch):
    #print(rolepolicymatch)
results = {'Users':userpolicymatch,'Groups':grouppolicymatch,'Roles':rolepolicymatch}
print(json.dumps(results))