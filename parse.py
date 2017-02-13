from xml.dom.minidom import parse,parseString
import sys,json

xml = parse('nvdcve-2.0-{}.xml'.format(sys.argv[1]))

def handle_entries():
    out = []
    for entry in xml.getElementsByTagName('entry'):
        out.append(entry)
    return out

def parse_cpe_uri(uri):
    part_dict = {
            'o': 'operating system',
            'h': 'hardware device',
            'a': 'application'
            }
    component_list = uri[5:].split(':')
    if len(component_list) == 7:
        return {
                'part': part_dict[component_list[0]],
                'vendor': component_list[1],
                'product': component_list[2],
                'version': component_list[3],
                'update': component_list[4],
                'edition': component_list[5],
                'lang': component_list[6]
                }
    elif len(component_list) == 6:
        return {
                'part': part_dict[component_list[0]],
                'vendor': component_list[1],
                'product': component_list[2],
                'version': component_list[3],
                'update': component_list[4],
                'edition': component_list[5]
                }
    elif len(component_list) == 5:
        return {
                'part': part_dict[component_list[0]],
                'vendor': component_list[1],
                'product': component_list[2],
                'version': component_list[3],
                'update': component_list[4]
                }
    elif len(component_list) == 4:
        return {
                'part': part_dict[component_list[0]],
                'vendor': component_list[1],
                'product': component_list[2],
                'version': component_list[3]
                }
    elif len(component_list) == 3:
        return {
                'part': part_dict[component_list[0]],
                'vendor': component_list[1],
                'product': component_list[2]
                }
    elif len(component_list) == 2:
        return {
                'part': part_dict[component_list[0]],
                'vendor': component_list[1]
                }
    elif len(component_list) == 1:
        return {
                'part': part_dict[component_list[0]]
                }

def get_cpe(entry):
    try:
        vsl = entry.getElementsByTagName('vuln:vulnerable-software-list')[0].childNodes
        cve = entry.getElementsByTagName('vuln:cve-id')[0].childNodes[0].toxml().split('-')
        out = []
        for item in vsl:
            if item.nodeType != item.TEXT_NODE:
                cpe = json.dumps(parse_cpe_uri(item.childNodes[0].toxml())).replace('"',"'")
                out.append(', '.join(['"'+cpe+'"']+cve))
        return out
    except Exception as e:
        pass
if __name__ == "__main__":
    entries = handle_entries()
    output = []
    for entry in entries:
        cpe = get_cpe(entry)
        output.append('\n'.join(cpe if cpe != None else ['']))
    open('{}.csv'.format(sys.argv[1]),'w').write('\n'.join(['cpe,cve,year,index']+output))

