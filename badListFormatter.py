import requests

dsBlock = "https://blacklists.isplicity.com/blacklists/ds-block.txt"
combined = "https://blacklists.isplicity.com/blacklists/combined.txt"
shDrop = "https://blacklists.isplicity.com/blacklists/sh-drop.txt"
shEDrop = "https://blacklists.isplicity.com/blacklists/sh-edrop.txt"
sslipBL = "https://blacklists.isplicity.com/blacklists/sslipblacklist.txt"

dsBlock = [f"{row.decode('utf-8').split('\t')[0]}/{row.decode('utf-8').split('\t')[2]}" for row in requests.get(dsBlock).content.split(b"\n") if len(row.decode('utf-8')) > 0 and row.decode('utf-8')[0] != "#"]
combined = [f"{row.decode('utf-8')}" for row in requests.get(combined).content.split(b"\n") if len(row.decode('utf-8')) > 0 and row.decode('utf-8')[0] != "#"]
shDrop = [f"{row.decode('utf-8').split(' ;')[0]}" for row in requests.get(shDrop).content.split(b"\n") if len(row.decode('utf-8')) > 0 and row.decode('utf-8')[0] != ";"]
shEDrop = [f"{row.decode('utf-8').split(' ;')[0]}" for row in requests.get(shEDrop).content.split(b"\n") if len(row.decode('utf-8')) > 0 and row.decode('utf-8')[0] != ";"]
sslipBL = [f"{row.decode('utf-8')}" for row in requests.get(sslipBL).content.split(b"\n") if len(row.decode('utf-8')) > 0 and row.decode('utf-8')[0] != "#"]


print('test')

def modifyCommand(before, listElement, after):
    if before and after != None:
        return f"{before}{listElement}{after}"
    elif before == None:
        return f"{listElement}{after}"
    elif after == None:
        return f"{before}{listElement}"

with open('/YOUR/FILE/PATH/HERE/firewall.rsc', 'w') as file:
    file.write("This is some text before each row\nThe \\n is needed for each new line\n\n")
    for ds in dsBlock:
        commandBeforeIp = "ip address add address="
        cammandAfterIp = None
        file.write(f"{modifyCommand(commandBeforeIp, ds, cammandAfterIp)}\n")

    for com in combined:
        commandBeforeIp = "ip firewall block some stuff address="
        cammandAfterIp = ' yummy'
        file.write(f"{modifyCommand(commandBeforeIp, com, cammandAfterIp)}\n")
    
    for sh in shDrop:
        commandBeforeIp = "ip firewall dropper dis shiz address="
        cammandAfterIp = None
        file.write(f"{modifyCommand(commandBeforeIp, sh, cammandAfterIp)}\n")

    for she in shEDrop:
        commandBeforeIp = "seems kinda sexists address="
        cammandAfterIp = ' kill it'
        file.write(f"{modifyCommand(commandBeforeIp, she, cammandAfterIp)}\n")

    for slip in sslipBL:
        commandBeforeIp = "black list is a bad word address="
        cammandAfterIp = None
        file.write(f"{modifyCommand(commandBeforeIp, she, cammandAfterIp)}\n")

    
