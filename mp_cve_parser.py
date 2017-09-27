# 'EStroev'
import csv
import os
import vulners_com
from datetime import datetime
from zipfile import ZipFile
import ijson
import pickle


def file_writer(outPathFile, data):
    with open(outPathFile, 'w', encoding='utf-8') as outFile:
        for id in data:
            outFile.write(
                f"ID: {data[id]['id']}\n\t"
                f"Title: {data[id]['title']}\n\t"
                f"URL: {data[id]['url']}\n\t"
                f"References: {'; '.join(data[id]['references'])}\n\t"
                f"CVE: {'; '.join(data[id]['cve'])}\n\t"
                f"CVSS: {data[id]['cvss']}\n\t"
                f"Type: {data[id]['type']}\n\n"
            )
    print(f'[+] Write {len(data)} entries to {outPathFile}')


def vulners_parser(in_file, out_path, pattern, search_object):
    print('[+] Vulners.com parser starts')
    zFile = ZipFile(in_file, 'r')
    for finfo in zFile.infolist():
        iFile = zFile.open(finfo)
        print('[+] Open "%s"' % in_file)
        parser = ijson.parse(iFile)
        data = dict()
        id, references, title, url, type, descr, cve, cvss = None, [], None, None, None, None, [], None
        searchDict = {
            'id': '',
            'references': '',
            'title': '',
            'url': '',
            'description': '',
            'cve': '',
            'cvss': ''
        }
        for prefix, event, value in parser:
            if prefix == '_index._index' == 'bulletins':
                id, references, title, url, type, descr, cve, cvss = None, [], None, None, None, None, [], None
                searchDict = {
                    'id': '',
                    'title': '',
                    'references': '',
                    'url': '',
                    'description': '',
                    'cve': '',
                    'cvss': ''
                }
            elif prefix == 'item._id':
                id = value
                searchDict['id'] = id
            elif prefix == 'item._source.title':
                title = value
                searchDict['title'] = title
            elif prefix == 'item._source.type':
                type = value
            elif prefix == 'item._source.href':
                url = value
                searchDict['url'] = url
            elif prefix == 'item._source.references.item':
                references.append(value)
                searchDict['references'] = references
            elif prefix == 'item._source.description':
                descr = value
                searchDict['description'] = descr
            elif prefix == 'item._source.cvss.score':
                cvss = str(value)
                searchDict['cvss'] = cvss
            elif prefix == 'item._source.cvelist.item':
                cve.append(value)
                searchDict['cve'] = cve

            if id and title and url and type and references and descr and cvss:
                if id == 'CVE-2005-1712':
                    print(f'[+] Find in {search_object}: {searchDict[search_object]}')
                    data[id] = {
                        'id': id,
                        'references': references,
                        'title': title,
                        'url': url,
                        'type': type,
                        'cve': cve,
                        'cvss': cvss
                    }
                    break
                id, references, title, url, descr, type, cve, cvss = None, [], None, None, None, None, [], None
                continue
            else:
                continue

        if data:
            file_writer(os.path.join(out_path, 'out.txt'), data)
            dump_data(os.path.join(out_path, 'vulners.pkl'), searchDict)
    print('[+] Vulners.com parser ends')

def dump_data(out_file, data):
    with open(out_file, 'wb') as fOut:
        pickle.dump(data, fOut)
    print(f'[+] Dump {len(data)} entries to {out_file}')


def mp_parser(in_file, out_file):
    print('[+] MP parser starts')
    parserDict = dict()
    with open(in_file, 'r') as file_in:
        print('[+] Open "%s"' % in_file)
        csv_f = csv.reader(file_in, delimiter=';')
        next(csv_f)  # skip header
        i = 0
        for line in csv_f:
            fqdn, softName, softVersion, host, cve, level, ScanStartTime = line
            if cve in parserDict:
                parserDict[cve]['host'].append(host)
                parserDict[cve]['soft'].append(softName)
                parserDict[cve]['version'].append(softVersion)
            else:
                parserDict[cve] = {
                    'host': [host],
                    'soft': [softName],
                    'version': [softVersion]
                }

    if parserDict:
        dump_data(out_file, parserDict)
    print('[+] MP parser starts')

    return parserDict


def main():
    mpFile = 'CVE from MP.csv'
    mpOutFile = 'mp_out.pkl'
    vulnersCVEFilePath = r"D:\Working\Projects\vulners.com\cve\cve.json.zip"
    vulnersOutPath = '.'

    startTime = datetime.now()
    print(startTime.strftime('[*] Start time: %d.%m.%Y %H:%M:%S'))
    mp_parser(in_file=mpFile, out_file=mpOutFile)
    vulners_parser(in_file=vulnersCVEFilePath, out_path=vulnersOutPath, search_object='id', pattern='')

    with open(mpOutFile, 'rb') as fIn:
        searchDict = pickle.load(fIn)

    # for cve in searchDict:
    #     if len(searchDict[cve]['host']) > 1:
    #         print(cve, searchDict[cve])
    endTime = datetime.now()
    print('[*] Total elapsed time - {0} seconds'.format((endTime - startTime).seconds))
    print(endTime.strftime('[*] End time: %d.%m.%Y %H:%M:%S'))


if __name__ == '__main__':
    main()