# 'EStroev'
from zipfile import ZipFile
import re
import os
import ijson
from datetime import datetime
import argparse


def file_writer(outPathFile, data):
    with open(outPathFile, 'a', encoding='utf-8') as outFile:
        for id in data:
            outFile.write(
                f"ID: {data[id]['id']}\n\t"
                f"Title: {data[id]['title']}\n\t"
                f"URL: {data[id]['url']}\n\t"
                f"CVE: {'; '.join(data[id]['cve'])}\n\t"
                f"CVSS: {data[id]['cvss']}\n\t"
                f"Type: {data[id]['type']}\n\n"
            )
    print(f'[+] Write {len(data)} entries to {outPathFile}')


def worker(inPath, outPathFile, pattern, searchObject):

    for root, dirs, files in os.walk(inPath):
        for file in files:
            if file.endswith('.zip'):
                inFilePath = os.path.join(root, file)
                zFile = ZipFile(inFilePath, 'r')
                for finfo in zFile.infolist():
                    iFile = zFile.open(finfo)

                    print('[+] Open %s ' % inFilePath)
                    parser = ijson.parse(iFile)

                    data = dict()

                    id, title, url, type, descr, cve, cvss = None, None, None, None, None, [], None
                    searchDict = {
                        'id': '',
                        'title': '',
                        'url': '',
                        'description': '',
                        'cve': '',
                        'cvss': ''
                    }
                    for prefix, event, value in parser:
                        if prefix == '_index._index' == 'bulletins':
                            id, title, url, type, descr, cve, cvss = None, None, None, None, None, [], None
                            searchDict = {
                                'id': '',
                                'title': '',
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
                            if pattern.search(searchDict[searchObject]):
                                print(f'[+] Find in {searchObject}: {searchDict[searchObject]}')
                                data[id] = {
                                    'id': id,
                                    'title': title,
                                    'url': url,
                                    'type': type,
                                    'cve': cve,
                                    'cvss': cvss
                                }
                            id, title, url, descr, type, cve, cvss = None, None, None, None, None, [], None
                            continue
                        else:
                            continue

                    if data:
                        file_writer(outPathFile, data)


def main():
    parser = argparse.ArgumentParser(description='Vulners.com DB parser')
    parser.add_argument('-o', dest='outFolder', action='store', help='Output folder')
    parser.add_argument('-f', dest='inPath', action='store', help='Input path')
    parser.add_argument('-p', dest='pattern', action='store', help='Searching pattern')
    parser.add_argument('-d', dest='searchObject', action='store', default='title', help='Search object')

    args = parser.parse_args()
    if not args.inPath:
        print('[-] You must specify an existing input path!')
        exit(-1)
    elif not os.path.exists(args.inPath):
        print('[-] Input path %s does not exist!' % os.path.abspath(args.inPath))
        exit(-1)
    if not args.pattern:
        print('[-] You must specify a searching pattern!')
        exit(-1)
    if not args.searchObject:
        print('[-] You must specify a searching object (id, title, url, description, cve, cvss)!')
        exit(-1)
    elif args.searchObject not in ['id', 'title', 'url', 'description', 'cve', 'cvss']:
        print('[-] You must specify one of the following objects: id, title, url, description, cve, cvss!')
        exit(-1)
    if not args.outFolder:
        print('[-] You must specify an existing path to the output file!')
        exit(-1)
    if not args.outFolder:
        print('[-] You must specify an existing path to the output folder!')
        exit(-1)
    elif not os.path.exists(args.outFolder):
        print(f'[-] Output folder {os.path.abspath(args.outFolder)} does not exist!')
        os.makedirs(args.outFolder)
        print(f'[+] Create output folder {args.outFolder}')

    outFile = os.path.join(args.outFolder, '{}_{}.txt'.format(args.searchObject, args.pattern.replace("\s", "_")))
    startTime = datetime.now()
    print(startTime.strftime('[*] Start time: %d.%m.%Y %H:%M:%S'))

    pattern = re.compile(args.pattern)

    if os.path.exists(outFile):
        os.remove(outFile)
        print(f'[-] Output file {outFile} exist! Removed it!')
    else:
        with open(outFile, 'w') as tmpFile:
            pass

    worker(args.inPath, outFile, pattern, args.searchObject)

    endTime = datetime.now()
    print('[*] Total elapsed time - {0} seconds'.format((endTime - startTime).seconds))
    print(endTime.strftime('[*] End time: %d.%m.%Y %H:%M:%S'))

if __name__ == '__main__':
    main()