import requests
import json

with open('variables.json', 'r') as file:
    variables = json.loads(file.read())


dsBlockUrl = "https://www.dshield.org/block.txt"
shDropUrl = "https://www.spamhaus.org/drop/drop.txt"
shEDropUrl = "https://www.spamhaus.org/drop/edrop.txt"
sslipBLUrl = "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt"


dsBlock = [f"{row.decode('utf-8').split('\t')[0]}/{row.decode('utf-8').split('\t')[2]}" for row in requests.get(dsBlock).content.split(b"\n") if len(row.decode('utf-8')) > 0 and row.decode('utf-8')[0] != "#"]
shDrop = [f"{row.decode('utf-8').split(' ;')[0]}" for row in requests.get(shDrop).content.split(b"\n") if len(row.decode('utf-8')) > 0 and row.decode('utf-8')[0] != ";"]
shEDrop = [f"{row.decode('utf-8').split(' ;')[0]}" for row in requests.get(shEDrop).content.split(b"\n") if len(row.decode('utf-8')) > 0 and row.decode('utf-8')[0] != ";"]
sslipBL = [f"{row.decode('utf-8')}" for row in requests.get(sslipBL).content.split(b"\n") if len(row.decode('utf-8')) > 0 and row.decode('utf-8')[0] != "#"]



def modifyCommand(before, listElement, after):
    if before and after != None:
        return f"{before}{listElement}{after}"
    elif before == None:
        return f"{listElement}{after}"
    elif after == None:
        return f"{before}{listElement}"

evalList = []

with open(f"{variables['default_filepath']}blacklist.rsc", 'w') as file:
    file.write("/ip firewall address-list\n:foreach i in=[find where list=blacklist] do={remove $i}\n\n")

    # for du in noDupList:
    #     commandBeforeIp = "add list=blacklist timeout=1d address="
    #     cammandAfterIp = None
    #     file.write(f"{modifyCommand(commandBeforeIp, du, cammandAfterIp)}\n")


    for ds in dsBlock:
        if ds not in evalList:
            commandBeforeIp = "add list=blacklist timeout=1d address="
            cammandAfterIp = None
            file.write(f"{modifyCommand(commandBeforeIp, ds, cammandAfterIp)}\n")
            evalList.append(ds)
    
    for sh in shDrop:
        if sh not in evalList:
            commandBeforeIp = "add list=blacklist timeout=1d address="
            cammandAfterIp = None
            file.write(f"{modifyCommand(commandBeforeIp, sh, cammandAfterIp)}\n")
            evalList.append(sh)

    for she in shEDrop:
        if she not in evalList:
            commandBeforeIp = "add list=blacklist timeout=1d address="
            cammandAfterIp = None
            file.write(f"{modifyCommand(commandBeforeIp, she, cammandAfterIp)}\n")
            evalList.append(she)

    for slip in sslipBL:
        if slip not in evalList:
            commandBeforeIp = "add list=blacklist timeout=1d address="
            cammandAfterIp = None
            file.write(f"{modifyCommand(commandBeforeIp, slip, cammandAfterIp)}\n")
            evalList.append(slip)

    
