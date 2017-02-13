from xml.etree.ElementTree import parse,tostring
import sys,json

xml = parse('nvdcve-2.0-{}.xml'.format(sys.argv[1])).getroot()
ns = {
        'cvss': 'http://scap.nist.gov/schema/cvss-v2/0.2',
        'vuln': 'http://scap.nist.gov/schema/vulnerability/0.4'
    }
def handle_entries():
    out = []
    for entry in xml:
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
        vsl = entry.find('vuln:vulnerable-software-list',ns)
        cve = entry.find('vuln:cve-id',ns).text.split('-')
        cvss = entry.find('vuln:cvss/cvss:base_metrics/cvss:score',ns).text
        out = []
        for item in vsl.iterfind('vuln:product',ns):
           cpe = json.dumps(parse_cpe_uri(item.text)).replace('"',"'")
           out.append(', '.join(['"'+cpe+'"',cvss]+cve))
        return out
    except:
        pass
if __name__ == "__main__":
    entries = handle_entries()
    output = []
    for entry in entries:
        cpe = get_cpe(entry)
        if cpe != None:
            output.append('\n'.join(cpe))
    open('{}.csv'.format(sys.argv[1]),'w').write('\n'.join(['cpe,cvss,cve,year,index']+output))

