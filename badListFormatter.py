import requests
import json
import datetime
import variables

timstampNow = datetime.datetime.now()



dsBlockUrl = "https://www.dshield.org/block.txt"
shDropUrl = "https://www.spamhaus.org/drop/drop.txt"
shEDropUrl = "https://www.spamhaus.org/drop/edrop.txt"
sslipBLUrl = "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt"


dsBlock = []
for row in requests.get(dsBlockUrl).content.split(b"\n"):
    if len(row.decode('utf-8')) > 0 and row.decode('utf-8')[0] != "#":
        rowList = row.decode('utf-8').split('\t')
        dsBlock.append(f"{rowList[0]}/{rowList[2]}")

shDrop = []
for row in requests.get(shDropUrl).content.split(b"\n"):
    if len(row.decode('utf-8')) > 0 and row.decode('utf-8')[0] != ";":
        shDrop.append(f"{row.decode('utf-8').split(' ;')[0]}")

shEDrop = []
for row in requests.get(shEDropUrl).content.split(b"\n"):
    if len(row.decode('utf-8')) > 0 and row.decode('utf-8')[0] != ";":
        shDrop.append(f"{row.decode('utf-8').split(' ;')[0]}")

sslipBL = []
for row in requests.get(sslipBLUrl).content.split(b"\n"):
    if len(row.decode('utf-8')) > 0 and row.decode('utf-8')[0] != "#":
        sslipBL.append(f"{row.decode('utf-8')}")


def modifyCommand(before, listElement, after):
    if before and after != None:
        return f"{before}{listElement}{after}"
    elif before == None:
        return f"{listElement}{after}"
    elif after == None:
        return f"{before}{listElement}"

evalList = []

with open(f"{variables.default_filepath}blacklist.rsc", 'w') as file:
    file.write(f"# Last Updated At: {timstampNow} \n")
    file.write("/ip firewall address-list\n:foreach i in=[find where list=blacklist] do={remove $i}\n\n")
    for ds in dsBlock:
        ds = ds.strip("\n")
        ds = ds.strip("\r")
        if ds not in evalList:
            commandBeforeIp = "add list=blacklist timeout=1d address="
            cammandAfterIp = " comment=dsBlock"
            file.write(f"{modifyCommand(commandBeforeIp, ds, cammandAfterIp)}\n")
            evalList.append(ds)
    
    for sh in shDrop:
        if sh not in evalList:
            sh = sh.strip("\n")
            sh = sh.strip("\r")
            commandBeforeIp = "add list=blacklist timeout=1d address="
            cammandAfterIp = " comment=shDrop"
            file.write(f"{modifyCommand(commandBeforeIp, sh, cammandAfterIp)}\n")
            evalList.append(sh)

    for she in shEDrop:
        she = she.strip("\n")
        she = she.strip("\r")
        if she not in evalList:
            commandBeforeIp = "add list=blacklist timeout=1d address="
            cammandAfterIp = " comment=shEDrop"
            file.write(f"{modifyCommand(commandBeforeIp, she, cammandAfterIp)}\n")
            evalList.append(she)

    for slip in sslipBL:
        slip = slip.strip("\n")
        slip = slip.strip("\r")
        if slip not in evalList:
            commandBeforeIp = "add list=blacklist timeout=1d address="
            cammandAfterIp = " comment=sslipBL"
            file.write(f"{modifyCommand(commandBeforeIp, slip, cammandAfterIp)}\n")
            evalList.append(slip)