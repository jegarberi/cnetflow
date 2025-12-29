import json



def main():
    output1 = ""
    outpout2 = ""
    output1 = "INSERT INTO ips VALUES "
    output2 = "INSERT INTO services VALUES "
    sevices = []
    with open("./conexiones_usuarios.json" ,"r") as file:
        content = file.read()
        services = json.loads(content)

    for service in services:
        #print(service)
        output1 += f"('{service['Nombre']}',{service['Nodo']},{service['Vlan']},'{service['Tipo']}','{service['IP']}'),"

    with open("./public_servers.json" ,"r") as file:
        content = file.read()
        services = json.loads(content)

    for service in services:
        #print(service)
        addr_cidr = service[0].split("/")
        addr = addr_cidr[0]
        cidr = addr_cidr[1]
        output2 += f"('{addr}',{service[1]},{service[2]},'{service[3]}','{cidr}'),"

    output1 = output1[0:len(output1)-1]
    output1 += ";"
    print(output1)


    output2 = output2[0:len(output2)-1]
    output2 += ";"
    print(output2)
    return





if __name__ == '__main__':
    main()