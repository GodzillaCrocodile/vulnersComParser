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
                # f"Host: {'; '.join(data[id]['host'])}\n\t"
                # f"Soft: {'; '.join(data[id]['soft'])}\n\t"
                f"Type: {data[id]['type']}\n\n"
            )
    print(f'[+] Write {len(data)} entries to {outPathFile}')


def vulners_parser(in_file, out_path, search_object, in_dict):
    print('[+] Vulners.com parser starts')
    startTime = datetime.now()
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
            'cvss': '',
            'host': '',
            'soft': ''
        }
        findCount = 0
        totalCVECount = len(in_dict)
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
                    'cvss': '',
                    'host': '',
                    'soft': ''
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

            if id and title and url and type and descr and cvss:
                if id in in_dict:
                    findCount += 1
                    print(f'[+] {findCount}/{totalCVECount}. Find in {search_object}: {searchDict[search_object]}. Number of hosts: {len(in_dict[id]["host"])}')
                    data[id] = {
                        'id': id,
                        'references': references,
                        'title': title,
                        'url': url,
                        'type': type,
                        'cve': cve,
                        'cvss': cvss,
                        'host': in_dict[id]['host'],
                        'soft': in_dict[id]['soft']
                    }
                    in_dict.pop(id)
                id, references, title, url, descr, type, cve, cvss = None, [], None, None, None, None, [], None
                continue
            else:
                continue

        if data:
            file_writer(os.path.join(out_path, 'out.txt'), data)

        if in_dict:
            with open('not_found.txt', 'w') as fOut:
                fOut.write('\n'.join([cve for cve in in_dict]))
            print(f'[+] {len(in_dict)} entries not found. Write to "not_found.txt"')
        # if searchDict:
        #     dump_data(os.path.join(out_path, 'vulners.pkl'), searchDict)
    print(f'[+] Total processed entries: {len(in_dict) + findCount}/{totalCVECount}')
    endTime = datetime.now()
    seconds = (endTime - startTime).seconds
    print(f'[*] Vulners.com parser ends - {seconds} seconds/{"%.2f" % int(seconds/60)} minutes')


def dump_data(out_file, data):
    with open(out_file, 'wb') as fOut:
        pickle.dump(data, fOut)
    print(f'[+] Dump {len(data)} entries to {out_file}')


def mp_parser(in_file, out_file, force=True):
    startTime = datetime.now()
    if force:
        print('[+] MP parser starts')
        parserDict = dict()
        with open(in_file, 'r') as file_in:
            print('[+] Open "%s"' % in_file)
            csv_f = csv.reader(file_in, delimiter=';')
            next(csv_f)  # skip header
            for line in csv_f:
                fqdn, softName, softVersion, host, cve, level, ScanStartTime = line
                if cve in parserDict:
                    if host not in parserDict[cve]['host']:
                        parserDict[cve]['host'].append(host)
                    if f'{softName}/{softVersion}' not in parserDict[cve]['soft']:
                        parserDict[cve]['soft'].append(f'{softName}/{softVersion}')
                else:
                    parserDict[cve] = {
                        'host': [host],
                        'soft': [f'{softName}/{softVersion}'],
                    }

        if parserDict:
            dump_data(out_file, parserDict)
    else:
        with open(out_file, 'rb') as fIn:
            parserDict = pickle.load(fIn)
        print(f'[+] Load {len(parserDict)} entries from {out_file}')

    endTime = datetime.now()
    seconds = (endTime - startTime).seconds
    print(f'[*] MP parser ends - {seconds} seconds/{"%.2f" % int(seconds/60)} minutes')

    return parserDict


def main():
    mpFile = 'CVE from MP.csv'
    mpOutFile = 'mp.pkl'
    vulnersCVEFilePath = r"D:\Working\Projects\vulners.com\cve\cve.json.zip"
    vulnersOutPath = '.'

    startTime = datetime.now()
    print(startTime.strftime('[*] Start time: %d.%m.%Y %H:%M:%S'))
    mpDict = mp_parser(in_file=mpFile, out_file=mpOutFile, force=False)
    vulners_parser(in_file=vulnersCVEFilePath, out_path=vulnersOutPath, search_object='id', in_dict=mpDict)

    endTime = datetime.now()
    seconds = (endTime - startTime).seconds
    print(f'[*] Total elapsed time - {seconds} seconds/{"%.2f" % int(seconds/60)} minutes')
    print(endTime.strftime('[*] End time: %d.%m.%Y %H:%M:%S'))


if __name__ == '__main__':
    main()