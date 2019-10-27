import os, sys, time
from datetime import datetime
import socket

import pandas as pd
import pandas as pd1
import pandas as pd_read
import pandas as pd_write
import pefile
import array
import math
import pickle
from sklearn.externals import joblib
import numpy as np
import hashlib
import argparse

#from NoribenSandbox_tr import revertSnapshot, startVM, suspendVM

from imutils import paths
import imutils
import shutil
import zipfile
import subprocess
from virus_total_apis import PublicApi as VirusTotalPublicApi

def get_entropy(data):
    if len(data) == 0:
	    return 0.0
		
    occurences = array.array('L', [0]*256)
#    print('\n\n get entropy data:', data, '\n')
	
    for x in data:
#        print('x in data:', x)
        occurences[x if isinstance(x, int) else ord(x)] += 1

    entropy = 0
    for x in occurences:
        if x:
            p_x = float(x) / len(data)     
            entropy -= p_x*math.log(p_x, 2)
#            print('x:', x, 'p_x', p_x, entropy)
    return entropy

def get_resources(pe):
    """Extract resources :
    [entropy, size]"""
    resources = []
    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        try:
            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if hasattr(resource_type, 'directory'):
                    for resource_id in resource_type.directory.entries:
                        if hasattr(resource_id, 'directory'):
                            for resource_lang in resource_id.directory.entries:
                                data = pe.get_data(resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size)
                                size = resource_lang.data.struct.Size
                                entropy = get_entropy(data)

                                resources.append([entropy, size])
        except Exception as e:
            return resources
    return resources

def get_version_info(pe):
    """Return version infos"""
    res = {}
    for fileinfo in pe.FileInfo:
        if fileinfo.Key == 'StringFileInfo':
            for st in fileinfo.StringTable:
                for entry in st.entries.items():
                    res[entry[0]] = entry[1]
        if fileinfo.Key == 'VarFileInfo':
            for var in fileinfo.Var:
                res[var.entry.items()[0][0]] = var.entry.items()[0][1]
    if hasattr(pe, 'VS_FIXEDFILEINFO'):
          res['flags'] = pe.VS_FIXEDFILEINFO.FileFlags
          res['os'] = pe.VS_FIXEDFILEINFO.FileOS
          res['type'] = pe.VS_FIXEDFILEINFO.FileType
          res['file_version'] = pe.VS_FIXEDFILEINFO.FileVersionLS
          res['product_version'] = pe.VS_FIXEDFILEINFO.ProductVersionLS
          res['signature'] = pe.VS_FIXEDFILEINFO.Signature
          res['struct_version'] = pe.VS_FIXEDFILEINFO.StrucVersion
    return res

def generate_MD5(filename, blocksize=65536):

	hash = hashlib.md5()
	
	with open(filename,"rb") as f:
		for block in iter(lambda: f.read(blocksize),b""):
			hash.update(block)
	
	return hash.hexdigest()

def extract_infos(fpath):
    res = {}

    Name = fpath[fpath.rfind('\\')+1 :]
    pe = pefile.PE(fpath)

    res['MD5'] = generate_MD5(fpath)

    res['Machine'] = pe.FILE_HEADER.Machine
    res['SizeOfOptionalHeader'] = pe.FILE_HEADER.SizeOfOptionalHeader
    res['Characteristics'] = pe.FILE_HEADER.Characteristics
    res['MajorLinkerVersion'] = pe.OPTIONAL_HEADER.MajorLinkerVersion
    res['MinorLinkerVersion'] = pe.OPTIONAL_HEADER.MinorLinkerVersion
    res['SizeOfCode'] = pe.OPTIONAL_HEADER.SizeOfCode
    res['SizeOfInitializedData'] = pe.OPTIONAL_HEADER.SizeOfInitializedData
    res['SizeOfUninitializedData'] = pe.OPTIONAL_HEADER.SizeOfUninitializedData
    res['AddressOfEntryPoint'] = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    res['BaseOfCode'] = pe.OPTIONAL_HEADER.BaseOfCode
    try:
        res['BaseOfData'] = pe.OPTIONAL_HEADER.BaseOfData
    except AttributeError:
        res['BaseOfData'] = 0
    res['ImageBase'] = pe.OPTIONAL_HEADER.ImageBase
    res['SectionAlignment'] = pe.OPTIONAL_HEADER.SectionAlignment
    res['FileAlignment'] = pe.OPTIONAL_HEADER.FileAlignment
    res['MajorOperatingSystemVersion'] = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
    res['MinorOperatingSystemVersion'] = pe.OPTIONAL_HEADER.MinorOperatingSystemVersion
    res['MajorImageVersion'] = pe.OPTIONAL_HEADER.MajorImageVersion
    res['MinorImageVersion'] = pe.OPTIONAL_HEADER.MinorImageVersion
    res['MajorSubsystemVersion'] = pe.OPTIONAL_HEADER.MajorSubsystemVersion
    res['MinorSubsystemVersion'] = pe.OPTIONAL_HEADER.MinorSubsystemVersion
    res['SizeOfImage'] = pe.OPTIONAL_HEADER.SizeOfImage
    res['SizeOfHeaders'] = pe.OPTIONAL_HEADER.SizeOfHeaders
    res['CheckSum'] = pe.OPTIONAL_HEADER.CheckSum
    res['Subsystem'] = pe.OPTIONAL_HEADER.Subsystem
    res['DllCharacteristics'] = pe.OPTIONAL_HEADER.DllCharacteristics
    res['SizeOfStackReserve'] = pe.OPTIONAL_HEADER.SizeOfStackReserve
    res['SizeOfStackCommit'] = pe.OPTIONAL_HEADER.SizeOfStackCommit
    res['SizeOfHeapReserve'] = pe.OPTIONAL_HEADER.SizeOfHeapReserve
    res['SizeOfHeapCommit'] = pe.OPTIONAL_HEADER.SizeOfHeapCommit
    res['LoaderFlags'] = pe.OPTIONAL_HEADER.LoaderFlags
    res['NumberOfRvaAndSizes'] = pe.OPTIONAL_HEADER.NumberOfRvaAndSizes
    
    # Sections
    res['SectionsNb'] = len(pe.sections)
    entropy = map(lambda x:x.get_entropy(), pe.sections)
#    print("extract info:", entropy)
    res['SectionsMeanEntropy'] = sum(entropy)/float(len(entropy))
    res['SectionsMinEntropy'] = min(entropy)
    res['SectionsMaxEntropy'] = max(entropy)
    raw_sizes = map(lambda x:x.SizeOfRawData, pe.sections)
    res['SectionsMeanRawsize'] = sum(raw_sizes)/float(len(raw_sizes))
    res['SectionsMinRawsize'] = min(raw_sizes)
    res['SectionsMaxRawsize'] = max(raw_sizes)
    virtual_sizes = map(lambda x:x.Misc_VirtualSize, pe.sections)
    res['SectionsMeanVirtualsize'] = sum(virtual_sizes)/float(len(virtual_sizes))
    res['SectionsMinVirtualsize'] = min(virtual_sizes)
    res['SectionMaxVirtualsize'] = max(virtual_sizes)

    #Imports
    try:
        res['ImportsNbDLL'] = len(pe.DIRECTORY_ENTRY_IMPORT)
        imports = sum([x.imports for x in pe.DIRECTORY_ENTRY_IMPORT], [])
        res['ImportsNb'] = len(imports)
        res['ImportsNbOrdinal'] = len(filter(lambda x:x.name is None, imports))
    except AttributeError:
        res['ImportsNbDLL'] = 0
        res['ImportsNb'] = 0
        res['ImportsNbOrdinal'] = 0

    #Exports
    try:
        res['ExportNb'] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
    except AttributeError:
        # No export
        res['ExportNb'] = 0
    #Resources
    resources= get_resources(pe)
    res['ResourcesNb'] = len(resources)
    
    if len(resources)> 0:
        entropy = map(lambda x:x[0], resources)
        res['ResourcesMeanEntropy'] = sum(entropy)/float(len(entropy))
        res['ResourcesMinEntropy'] = min(entropy)
        res['ResourcesMaxEntropy'] = max(entropy)
        sizes = map(lambda x:x[1], resources)
        res['ResourcesMeanSize'] = sum(sizes)/float(len(sizes))
        res['ResourcesMinSize'] = min(sizes)
        res['ResourcesMaxSize'] = max(sizes)
    else:
        res['ResourcesNb'] = 0
        res['ResourcesMeanEntropy'] = 0
        res['ResourcesMinEntropy'] = 0
        res['ResourcesMaxEntropy'] = 0
        res['ResourcesMeanSize'] = 0
        res['ResourcesMinSize'] = 0
        res['ResourcesMaxSize'] = 0

    # Load configuration size
    try:
        res['LoadConfigurationSize'] = pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.Size
    except AttributeError:
        res['LoadConfigurationSize'] = 0

    # Version configuration size
    try:
        version_infos = get_version_info(pe)
        res['VersionInformationSize'] = len(version_infos.keys())
    except AttributeError:
        res['VersionInformationSize'] = 0

    return res
     
def final_vote(results):	
    final_result = 0
    temp = results
    for mlr in temp:
        if temp[mlr] == 0:
            temp[mlr] = 1
        else:
            temp[mlr] = 0			
        final_result = final_result+temp[mlr]
			
        if final_result > 3:
            print 'This sample is malicious'
            return 1
            break
    if final_result < 3:
        print 'This sample is legitimate'
        return 0 


def files_to_timestamp(path):
    files = [os.path.join(path, f) for f in os.listdir(path)]
    return dict ([(f, os.path.getmtime(f)) for f in files])

def create_dir(path_name):
    if not os.path.exists(path_name):
	os.makedirs(path_name)

def open_download_dump(temp, file_path, url_table):
    f_out = open(file_path, 'r')

    for num, r in enumerate(f_out):
        r1, r2 = r.split()
              #  print r1, r2
        if temp == None: # first record
            create_dir('./'+r1)
            url_table[r2] = 0
            temp = r2
            os.system( "wget -P " + './' + r1 + ' ' + r2)
        elif temp != None:
                   # print 'temp != None'
            if (r2 not in url_table):
                create_dir('./'+r1)
                url_table[r2] = 0 
                temp = r2
                os.system( "wget -P " + './'+ r1 + ' ' + r2)
            elif(r2 in url_table): # subsequent record
                url_table[r2] = url_table[r2] + 1        
    f_out.close()
    return temp, url_table                 
                    
def connect_to_client(host, msg = 'test', port = 54321): 
  # Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect the socket to the port where the server is listening
    server_address = (host, 10000)
    print >>sys.stderr, 'connecting to %s port %s' % server_address
    sock.connect(server_address)

    try:
    
    # Send data
        message = msg
        print >>sys.stderr, 'sending "%s"' % message
        sock.sendall(message)

    # Look for the response
        amount_received = 0
        amount_expected = len(message)
    
        while amount_received < amount_expected:
            data = sock.recv(1024)
            amount_received += len(data)
            print >>sys.stderr, 'received "%s"' % data

    finally:
        print >>sys.stderr, 'closing socket'
        sock.close()

def open_meta_file(file_path):
    f_out = open(file_path, 'r')

    for num, r in enumerate(f_out):
        r1 = r.split()
        if 'DST' in r1[0]:
            if 'IP' in r1[1]:
                des_ip = r1[2]
        elif 'HTTP' in r1[0]:
            if 'URI' in r1[1]:
                file_name = r1[2]
            elif 'REFERER' in r1[1]:
                referer = r1[2]
    full_url = referer + file_name[file_name.rfind('/')+1:]

    f_out.close()
    return des_ip, full_url

def static_detection(file_name):

    print 'Get file: ', file_name

    # Load classifier
    ml = {}
    normalise_model = {}
    fl = {}
    ml_folder = []
    ml_class = []
    dir = "./"
    for f in os.listdir(dir):
        if os.path.isdir(dir + '\\' + f):
            if 'static_classifier' in f:
                ml_folder.append(f)
                ml[f] = {}
                normalise_model[f] = {}
                fl[f] = {}
                for cl in os.listdir(dir + '\\' + f):
                    if os.path.isfile(dir + '\\' + f + '\\' + cl):
                        if 'PCA' in cl and 'feature' not in cl:
                            normalise_model[f]['PCA'] = joblib.load(os.path.join(os.path.dirname(os.path.realpath(__file__)),f + '/' + cl)) 
                        elif 'MinMaxScaler' in cl and 'feature' not in cl:
                            normalise_model[f]['MinMaxScaler'] = joblib.load(os.path.join(os.path.dirname(os.path.realpath(__file__)),f + '/' + cl)) 							
                        elif 'classifier' in cl:
                            ml_class.append(cl)						
                            ml[f][cl] = joblib.load(os.path.join(os.path.dirname(os.path.realpath(__file__)),f + '/' + cl))							
                        elif 'feature' in cl and 'pca' not in cl and 'MinMax' not in cl:							
                            fl[f][cl] = pickle.loads(open(os.path.join(os.path.dirname(os.path.realpath(__file__)),f + '/' + cl),'rb').read())

    data = extract_infos(file_name)

	#Extract feature for each model and process the pe data with the feature
    pe_feature = {}
    for first in fl:
        pe_feature[first] = {}
        for second in fl[first]:
            pe_feature[first][second] = map(lambda x:data[x], fl[first][second])
	
    # Normalization and PCA
    for folder in pe_feature:
        for machine_model in pe_feature[folder]:
            Loaded_MinMaxScaler = normalise_model[folder]['MinMaxScaler']
            Loaded_pca = normalise_model[folder]['PCA']
			
            temp = np.reshape(pe_feature[folder][machine_model],(1, len(pe_feature[folder][machine_model])))
			
            pe_feature[folder][machine_model] = Loaded_MinMaxScaler.transform(temp)
            pe_feature[folder][machine_model] = Loaded_pca.transform(pe_feature[folder][machine_model])
	
    print 'Normalization completed'
    result = {}
	#predict the sample using the ml model
    for first in ml:
        result[first] = {}
        for ml_second, fl_second in zip(ml[first], pe_feature[first]):
            loaded_ml = ml[first][ml_second]
            raw_data = pe_feature[first][fl_second]     #feature heading
            result[first][ml_second] = loaded_ml.predict(raw_data)
    
    print('The file %s' % (file_name)) #,['malicious', 'legitimate'][res]))
			
    final_result = 0
    	
    for f in result:
        final_result = final_vote(result[f])

    return final_result

def check_molicious(file_name, result, r1):
    print result
    if result == 0:
       connect_to_client(r1, 'This is malicious file:' + file_name)
    else:
       connect_to_client(r1, 'This is legitimate file:' + file_name)

def exractFeatureFromRegistry(processedData, header, for_record, col):
    reg = []
    reg = ['RegSetValue', 'RegDeleteKey', 'RegDeleteValue', 'SetSecurityFile']
    num_setvalue_reg = 0
    num_deletekey_reg = 0
    num_reg_value = {reg[0]:0, reg[1]:0, reg[2]:0, reg[3]:0}
    process_create = 'Process Create'
    num_process_create = 0
    process_create_list = []

    for i, r in enumerate(processedData[header[2]]): #operation column is selected
        if r == reg[0]:
            num_reg_value[reg[0]] = num_reg_value[reg[0]] + 1
        elif r == reg[1]:
            num_reg_value[reg[1]] = num_reg_value[reg[1]] + 1
        elif r == reg[2]:
            num_reg_value[reg[2]] = num_reg_value[reg[2]] + 1
        elif r == reg[3]:
            num_reg_value[reg[3]] = num_reg_value[reg[3]] + 1
        elif r == process_create:
            if processedData[header[0]][i] == 'python.exe':
                continue
            else:
                num_process_create = num_process_create + 1
                process_create_list.append(i)

        if isinstance(processedData[header[3]][i], basestring) == False: #check for NAN 
            continue

    for c in reg:
        col.append(c)		
        for_record[c]=num_reg_value[c]

    for_record['TotalReg']=  num_reg_value[reg[0]] + num_reg_value[reg[1]] + num_reg_value[reg[2]] + num_reg_value[reg[3]]  	
    col.append('TotalReg')

    check = 0
    temp = processedData[header[3]][0]
    limits = 50  #len(processedData[header[3]])
    temp_check = np.zeros(len(processedData[header[3]]), dtype=bool)

	#-----------------------------Process Create feature---------------------------------------------------------

    for_record['ProcessCreate']=num_process_create
    col.append('ProcessCreate')
	
    return True

def check_for_encrypt_formate(full_path_file_name, file_name, format = '.zip'): # remove the encryption format
    dot_index = 0
    dot_index = full_path_file_name.rfind('.')
    if (file_name.count('.') > 1) and (format in file_name[:file_name.rfind('.')]): #check for encrypted file 
        return full_path_file_name[:dot_index]
    else:
        return full_path_file_name

def extractFeatureFromEncryption(mining_mtrix, processedData, header, for_record, col, format='.zip', num_of_file = 15):

    step_limit = num_of_file
    pos = 3
    encrypt_len = 0
#----------------------------------------------------------------------
    encrypt_cal_op = {'CreateFile': 25.6, 'SetDispositionInformationFile':51.2 \
               ,'SetRenameInformationFile':102.4, 'SetAllocationInformationFile':204.8}
    encrypt_cal_desired_access = {' Generic Read':0.2, ' Read Attributes':0.1, ' Read Control':0.4, ' Write Attributes':0.8, 'Write':1.6, ' Write Data':3.2, ' Generic Write':6.4, 'Add File':12.8,\
                               ' True':0.1, ' False':0.2}
    encrypt_cal_disposition =  {' Open':0.001, ' Close':0.002, ' OpenIf':0.004, ' OverwriteIf':0.008, ' Create':0.016, ' FileName':0.001}
    encrypt_cal_sharemode = {' None':0, ' Read':0.00001, ' Read Attributes':0.00002, ' Write':0.00004, ' Delete':0.00008}
    encrypt_cal_openresult = {' Opened':0.000001, ' Closed':0.000002, ' Created':0.000004}
 	   
#----------------------------------------------------------------------
 #   mining_mtrix = {}
    metrix_inddex = {}
    left_over = 0
    num_of_encryption_step = 0
    total_encrypt_len = []
    encrypt_format = False
    print 'mining_mtrix:', len(mining_mtrix)

#get 5 simples of zip 
    for i in range(len(processedData[header[pos]])):
        if isinstance(processedData[header[pos]][i], basestring) == False: #Skip the loop if not string
            continue

        full_path_file_name = processedData[header[pos]][i]
        index_num = processedData[header[pos]][i].rfind('\\') + 1 
        file_name = processedData[header[pos]][i][index_num:] 
	

       # print full_path_file_name	
        if len(mining_mtrix) < step_limit: 
            
            if format in file_name: #check the format from the last 4 char in the file name 
                
                processed_file_name = check_for_encrypt_formate(full_path_file_name, file_name, format)
					
                if (processed_file_name in mining_mtrix) == False: # if selected file name is not in matrix then add into first record
                    mining_mtrix[processed_file_name] = [i] #file name 
                    metrix_inddex[processed_file_name] = 1
                else:                                                # Add as subsequent record
                    mining_mtrix[processed_file_name].append(i)
                    metrix_inddex[processed_file_name] = metrix_inddex[processed_file_name] + 1
				
            if len(processedData[header[pos]]) == (i + 2): # Reach the end of the log and the mining matrix is still not fill n n
#                print len(processedData[header[pos]])
#                print 'insufficient mining', len(processedData[header[pos]]) 
                return False
            else:
                continue

 #       print 'length of mining_mtrix', mining_mtrix
		
        num_of_encryption_step = metrix_inddex[max(metrix_inddex, key = metrix_inddex.get)]
        if left_over == 0:
            for mining_i in mining_mtrix:
                #print 'in the matrix :', mining_i
                for num in range(1,num_of_encryption_step):
                    if len(mining_mtrix[mining_i]) < num + 1: #2: This is going in acsending 
                        left_over = left_over + (num_of_encryption_step - num) #2 This is going in decending 
                       # print 'left over : ', left_over
                        break 
				
        if (format in processedData[header[pos]][i]) == False:
            continue
            
        
  #      remove_format = check_for_encrypt_formate(full_path_file_name, file_name, format).rfind('.')
        file_name_done = check_for_encrypt_formate(full_path_file_name, file_name, format)

        for mined in mining_mtrix:
            if processedData[header[pos]][i] in mined: 
                mining_mtrix[file_name_done].append(i)
                metrix_inddex[file_name_done] = metrix_inddex[file_name_done] + 1
                left_over = left_over - 1
                break

        if left_over == 0:
           # print metrix_inddex
            break

    for num in mining_mtrix:
        total_encrypt_len.append(mining_mtrix[num][-1] - mining_mtrix[num][0] + 1)
#calculate the avg, max of encrypt length

    if len(mining_mtrix) > 0:
        if  len(mining_mtrix) == 1:
#            print 'Insufficient record for calculation'
            return False

        print 'encryption step :', len(mining_mtrix.values()[0])
#        print total_encrypt_len
        print 'encryption min length :', min(total_encrypt_len), 'encryption max length :', max(total_encrypt_len)
        print 'encryption mean :', np.mean(total_encrypt_len)
    
        for i in range(len(mining_mtrix.values()[0])):
#            print  total_encrypt_procedure[0][i], ': ', processedData[header[2]][total_encrypt_procedure[0][i]], "\t", processedData[header[3]][total_encrypt_procedure[0][i]]
            temp_detail = processedData[header[5]][mining_mtrix.values()[0][i]].split(',')
 #           print temp_detail
            point = encrypt_cal_op[processedData[header[2]][mining_mtrix.values()[0][i]]]
            for j in range(len(temp_detail)): #
                if ':' in temp_detail[j]: # Check for all :
                    temp = temp_detail[j].split(':')
                    if 'Desired Access' in temp[0]: 
                        if '/' in temp[1]:
                            read_write = temp[1].split('/')
                            #print 'read write', read_write[0], read_write[1], len(read_write)
                            point = point + encrypt_cal_desired_access[read_write[0]]
                            point = point + encrypt_cal_desired_access[read_write[1]]
                        else:
                            point = point + encrypt_cal_desired_access[temp[1]]			
                    elif 'Disposition' in temp[0]:
                        point = point + encrypt_cal_disposition[temp[1]]
                    elif 'ShareMode' in temp[0]:
                        point = point + encrypt_cal_sharemode[temp[1]]
                    elif 'OpenResult' in temp[0]:
                        point = point + encrypt_cal_openresult[temp[1]]
                    elif 'ReplaceIfExists' in temp[0]:
                        point = point + encrypt_cal_desired_access[temp[1]]
                    elif 'FileName' in temp[0]:
                        point = point + encrypt_cal_disposition[temp[0]]
                    elif 'Delete' in temp[0]:
                        point = point + encrypt_cal_desired_access[temp[1]] 
                elif 'Read' in temp_detail[j] or 'Write' in temp_detail[j]:
                    point = point + encrypt_cal_sharemode[temp_detail[j]]

            print i, ' Encryption point : ', point
            for_record['Enc'+str(i+1)] = point
            col.append('Enc'+str(i+1))
	
        if len(mining_mtrix.values()[0]) < 7:
            for i in range(len(mining_mtrix.values()[0])+1, 7):
                for_record['Enc'+str(i)] = 0 
                col.append('Enc'+str(i))

        for_record['EncryptionStep'] = len(mining_mtrix.values()[0])
        for_record['EncryptionMin'] = min(total_encrypt_len) 
        for_record['EncryptionMax'] = max(total_encrypt_len)
        for_record['EncryptionMean']= np.mean(total_encrypt_len)
        col.append('EncryptionStep')
        col.append('EncryptionMin')
        col.append('EncryptionMax')
        col.append('EncryptionMean')
        return True
    else:

        return False



def white_list():

    white_list_info ={ 'README.HTML':'C:\\Program Files\\Common Files\\microsoft shared\\OFFICE15\\1033', \
                 'README.txt':'C:\\Program Files\\Java\\jre1.8.0_101', \
                  'THIRDPARTYLICENSEREADME-JAVAFX.txt':'C:\\Program Files\\Java\\jre1.8.0_101', \
                  'THIRDPARTYLICENSEREADME.txt':'C:\\Program Files\\Java\\jre1.8.0_101' }


def extractFeatureFromMsg(total_encrypt_procedure, processedData, header, for_record, col):
    msg_file = ''
    ransom_note_pos = 0
    point_file = 'NoribenReports.zip'
	# mining_mtrix.values()[0][0] # This is the first encrypted file position 
    point_dir =  processedData[header[3]][total_encrypt_procedure.values()[0][0]][:processedData[header[3]][total_encrypt_procedure.values()[0][0]].rfind('\\')].upper()
    store_msg = []
    got_msg = False
    is_msg = False # check whether the current file is a message file
	
	
#    print 'Check msg file.... Start from:',  processedData[header[3]][total_encrypt_procedure.values()[0][0]]
#    print 'point dir is :', point_dir
    for i in range(25):     #This is to extract the display file, for after the encryption of file in a folder
        if 	total_encrypt_procedure.values()[0][0] + i > len(processedData[header[3]]):
            break

        if isinstance(processedData[header[3]][total_encrypt_procedure.values()[0][0] + i], basestring):
            
            to_upper = processedData[header[3]][total_encrypt_procedure.values()[0][0] + i].upper()
            is_msg = False
            if ('HELP_' in to_upper) or \
                ('_HOWDO' in to_upper) or \
                ('RECOVER' in to_upper) or \
                ('README' in to_upper) or \
                ('RESTORE' in to_upper) or \
                ('_README' in to_upper) or \
                ('README_' in to_upper) or \
                ('DECRYPT' in to_upper) or \
                ('READ___ME' in to_upper) or \
                ('UPDATES' in to_upper) or \
                ('_READ_TH' in to_upper):
   #             print  total_encrypt_procedure.values()[0][0], 'Path passed first part:', to_upper
                if point_dir in to_upper: 
                    if (processedData[header[3]][total_encrypt_procedure.values()[0][0] + i] in store_msg):
                        continue
                    else:
                        store_msg.append(processedData[header[3]][total_encrypt_procedure.values()[0][0] + i])
 #                   print processedData[header[3]][total_encrypt_procedure[0][0] + i]

                    got_msg = True
                    is_msg = True
                    continue
		
            if (got_msg == True) and (is_msg == False):
 #               print 'There are ', len(store_msg), ' ransom message'
                for m in range(len(store_msg)):
                    temp = store_msg[m][store_msg[m].rfind('\\') + 1:]
                    print temp
                    msg_file = msg_file + ';' + temp
					
                ransom_note_pos = 2
 #               print 'Ransomware position: ', ransom_note_pos
                break
    
    htm_file = {}
    htm_different = {} #differences in name for file with same keyword
    htm_rear_file = {}
    htm_rear_different = {}
    htm_temp = {}
    htm_rear = []
    htm_file_loc = {}
    htm_rear_loc = {}
    jpg_file = {}
    jpg_different = {}
    jpg_temp = {}
    jpg_file_loc = {}
    jpg_rear_file = {}
    jpg_rear_different = {}
    jpg_rear_temp = []
    jpg_rear_loc = {}
    bmp_file = {}
    bmp_different = {}
    bmp_temp = {}
    bmp_file_loc = {}

    txt_file = {}
    txt_different = {}
    txt_temp = []
    txt_file_loc = {}
    txt_rear_file = {}
    txt_rear_temp = []
    txt_rear_different = {}
    txt_rear_loc = {}
	
    start_counting = 0
    if got_msg == False: #This is to retrieve the msg by checking each folder. In theory the ransom mnessage will have more file than other
#        print 'Step 1 fail. Continue with step 2.'
        for file_ in processedData[header[3]]:
            if isinstance(file_, basestring):
                msg_index = file_.rfind('\\')
                text_len = len(file_)
                front_temp = file_[msg_index + 1: msg_index + 6]
                back_temp = file_[(text_len - 10):]
 #               print file_
                if ('.htm' in file_) or ('.html' in file_) or ('.HTML' in file_):
                    if (front_temp in htm_file) == False:  # for the new record 
                        htm_file[front_temp] = 1
                        htm_file_loc[front_temp]= file_
                        htm_temp[front_temp] = [file_[msg_index + 1:]] #store the first file for different
                        htm_different[front_temp] = 0
                     
 #                       print 'htm file', temp, htm_file
                    else:   #For existing file
                        htm_file[front_temp] = htm_file[front_temp] + 1
                        htm_file_loc[front_temp] = file_
						
                        if (file_[msg_index + 1:] in htm_temp[front_temp]) == False:  #
                            htm_different[front_temp] = htm_different[front_temp] + 1

                        htm_temp[front_temp].append(file_[msg_index + 1:])				
						
                    if (back_temp in htm_rear_file) == False:
                        htm_rear_file[back_temp] = 1
                        htm_rear_loc[back_temp]= file_
                    else:
                        htm_rear_file[back_temp] = htm_rear_file[back_temp] + 1
                        htm_rear_loc[back_temp] = file_	
			
						
                elif ('jpg' in file_) or ('png' in file_):
                    if (front_temp in jpg_file) == False:
                        jpg_file[front_temp] = 1
                        jpg_file_loc[front_temp]= file_
                        jpg_temp[front_temp] = [file_[msg_index + 1:]] #store the first file for different
                        jpg_different[front_temp] = 0
                    else:
                        jpg_file[front_temp] = jpg_file[front_temp] + 1
                        jpg_file_loc[front_temp] = file_    
						
                        if (file_[msg_index + 1:] in jpg_temp[front_temp]) == False:  #
                            jpg_different[front_temp] = jpg_different[front_temp] + 1

                        jpg_temp[front_temp].append(file_[msg_index + 1:])		
						
                    if (back_temp in jpg_rear_file) == False:
                        jpg_rear_file[back_temp] = 1
                        jpg_rear_loc[back_temp]= file_
                    else:
                        jpg_rear_file[back_temp] = jpg_rear_file[back_temp] + 1
                        jpg_rear_loc[back_temp] = file_	
						
                elif 'bmp' in file_:
                    if (front_temp in bmp_file) == False:
                        bmp_file[front_temp] = 1
                        bmp_file_loc[front_temp]= file_[msg_index + 1:]

                    else:
                        bmp_file[front_temp] = bmp_file[front_temp] + 1
                        bmp_file_loc[front_temp] = file_    						
						
                elif 'txt' in file_:
                    if (front_temp in txt_file) == False:
                        txt_file[front_temp] = 1
                        txt_file_loc[front_temp]= file_
                    else:
                        txt_file[front_temp] = txt_file[front_temp] + 1
                        txt_file_loc[front_temp] = file_

                    if (back_temp in txt_rear_file) == False:
                        txt_rear_file[back_temp] = 1
                        txt_rear_loc[back_temp]= file_
                    else:
                        txt_rear_file[back_temp] = txt_rear_file[back_temp] + 1
                        txt_rear_loc[back_temp] = file_						
			
      #  print 'htm show :', htm_file
      #  print 'jpg png show:', jpg_file
      #  print 'txt show:', txt_file
		
        if (len(htm_file) == 0):
            htm_max = 0
            max_htm_label = 0
        else:
            htm_max = htm_file[max(htm_file, key=htm_file.get)]
            max_htm_label = max(htm_file, key=htm_file.get)
			
        if (len(htm_rear_file) == 0):
            htm_rear_max = 0
            max_htm_rear_label = 0
        else:
            htm_rear_max = htm_rear_file[max(htm_rear_file, key=htm_rear_file.get)]
            max_htm_rear_label = max(htm_rear_file, key=htm_rear_file.get) 

        if (len(jpg_file) == 0):
            jpg_max = 0
            max_jpg_label = 0
        else:
            jpg_max = jpg_file[max(jpg_file, key=jpg_file.get)]
            max_jpg_label = max(jpg_file, key=jpg_file.get)
			
        if (len(jpg_rear_file) == 0):
            jpg_rear_max = 0
            max_jpg_rear_label = 0
        else:
            jpg_rear_max = jpg_rear_file[max(jpg_rear_file, key=jpg_rear_file.get)]
            max_jpg_rear_label = max(jpg_rear_file, key=jpg_rear_file.get)      
						
        if (len(txt_file) == 0):
            txt_max = 0
            max_txt_label = 0
        else:
            txt_max = txt_file[max(txt_file, key=txt_file.get)]
            max_txt_label = max(txt_file, key=txt_file.get)
			
        if (len(txt_rear_file) == 0):
            txt_rear_max = 0
            max_txt_rear_label = 0
        else:
            txt_rear_max = txt_rear_file[max(txt_rear_file, key=txt_rear_file.get)]
            max_txt_rear_label = max(txt_rear_file, key=txt_rear_file.get)          
			
        max_occurance= { 'htm':htm_max,\
                             'jpg' : jpg_max,\
                             'txt' : txt_max}

        max_occurance_label= { 'htm':max_htm_label,\
                             'jpg' : max_jpg_label,\
                             'txt' : max_txt_label}
							 
        max_rear_occurance= { 'htm': htm_rear_max,\
                             'jpg' : jpg_rear_max,\
                             'txt' : txt_rear_max}

        max_rear_occurance_label= { 'htm': max_htm_rear_label,\
                                   'jpg' : max_jpg_rear_label,\
                                   'txt' : max_txt_rear_label}
			
      #  print 'max occurance:', max_occurance	
      #  print 'label :', 	max_occurance_label	
        #
        num_folder = 250   # Message is in every folder
		
        if (max_occurance['htm'] > num_folder) or (max_occurance['jpg'] > num_folder) or (max_occurance['txt'] > num_folder):
            if (max_occurance_label['htm'] == max_occurance_label['jpg']) and (max_occurance_label['htm'] == max_occurance_label['txt']):
                store_msg.append(htm_file_loc[max_occurance_label['htm']])
                store_msg.append(jpg_file_loc[max_occurance_label['jpg']])
                store_msg.append(txt_file_loc[max_occurance_label['txt']])
            elif max_occurance_label['htm'] == max_occurance_label['jpg']:
                store_msg.append(htm_file_loc[max_occurance_label['htm']])
                store_msg.append(jpg_file_loc[max_occurance_label['jpg']])
            elif max_occurance_label['htm'] == max_occurance_label['txt']:
                store_msg.append(htm_file_loc[max_occurance_label['htm']])
                store_msg.append(txt_file_loc[max_occurance_label['txt']])
            elif max_occurance_label['txt'] == max_occurance_label['jpg']:
                store_msg.append(txt_file_loc[max_occurance_label['txt']])
                store_msg.append(jpg_file_loc[max_occurance_label['jpg']])
            elif (max_occurance['htm'] > max_occurance['jpg']) and (max_occurance['htm'] > max_occurance['txt']):
                store_msg.append(htm_file_loc[max_occurance_label['htm']])
            elif (max_occurance['jpg'] > max_occurance['htm']) and (max_occurance['jpg'] > max_occurance['txt']):
                store_msg.append(jpg_file_loc[max_occurance_label['jpg']])		
            elif (max_occurance['txt'] > max_occurance['jpg']) and (max_occurance['txt'] > max_occurance['htm']):
                store_msg.append(txt_file_loc[max_occurance_label['txt']])	

#            print 'store msg :', len(store_msg)			
            if len(store_msg)  > 0: 
                got_msg = True
        		
        elif (max_rear_occurance['htm'] > num_folder) or (max_rear_occurance['jpg'] > num_folder) or (max_rear_occurance['txt'] > num_folder):
            if max_rear_occurance_label['htm'] == max_rear_occurance_label['jpg'] and max_rear_occurance_label['htm'] == max_rear_occurance_label['txt']:
                store_msg.append(htm_rear_loc[max_rear_occurance_label['htm']])
                store_msg.append(jpg_rear_loc[max_rear_occurance_label['jpg']])
                store_msg.append(txt_rear_loc[max_rear_occurance_label['txt']])
            elif max_rear_occurance_label['htm'] == max_rear_occurance_label['jpg']:
                store_msg.append(htm_rear_loc[max_rear_occurance_label['htm']])
                store_msg.append(jpg_rear_loc[max_rear_occurance_label['jpg']])
            elif max_rear_occurance_label['htm'] == max_rear_occurance_label['txt']:
                store_msg.append(htm_rear_loc[max_rear_occurance_label['htm']])
                store_msg.append(txt_rear_loc[max_rear_occurance_label['txt']])
            elif max_rear_occurance_label['txt'] == max_rear_occurance_label['jpg']:
                store_msg.append(txt_rear_loc[max_rear_occurance_label['txt']])
                store_msg.append(jpg_rear_loc[max_rear_occurance_label['jpg']])
            elif (max_rear_occurance['htm'] > max_rear_occurance['jpg']) and (max_rear_occurance['htm'] > max_rear_occurance['txt']):
                store_msg.append(htm_rear_loc[max_rear_occurance_label['htm']])
            elif (max_rear_occurance['jpg'] > max_rear_occurance['htm']) and (max_rear_occurance['jpg'] > max_rear_occurance['txt']):
                store_msg.append(jpg_rear_loc[max_rear_occurance_label['jpg']])		
            elif (max_rear_occurance['txt'] > max_rear_occurance['jpg']) and (max_rear_occurance['txt'] > max_rear_occurance['htm']):
                store_msg.append(txt_rear_loc[max_rear_occurance_label['txt']])	
				
 #           print 'store msg :', len(store_msg)			
            if len(store_msg)  > 0: 
                got_msg = True
		
        if got_msg == True:
#            print 'There are ', len(store_msg), ' ransom message'
            for m in range(len(store_msg)):
                temp = store_msg[m][store_msg[m].rfind('\\') + 1:]
#                print temp
                msg_file = msg_file + ';' + temp
            ransom_note_pos = 2
            print 'Ransomware Position: ' , ransom_note_pos		
        elif len(htm_different) > 0: 
            if (htm_different[max(htm_different, key = htm_different.get)] > 10):
                store_msg.append(htm_temp[max(htm_different, key = htm_different.get)][0])
                for m in bmp_file:
                    if (m in htm_temp):
                        store_msg.append(bmp_file_loc[m])			

                msg_file = store_msg[0]
                msg_file = msg_file + ';' + store_msg[-1]
                ransom_note_pos = 3
                got_msg = True
 #               print 'There are ', len(store_msg), ' ransom message', store_msg
 #               print 'Ransomware Position: ' , ransom_note_pos		
            
			
    all_file = []
    all_num = []
    total_record = len(processedData[header[3]])
    first_few_file = 700 #For tweeting the config
    num_attempt = 0
	

    if got_msg == False: 
        while (len(store_msg) == 0):    
  #          print 'Step 1 and 2 fail. Continue with step 3.'
            for i, r in enumerate(processedData[header[2]]): #operation column is selected
                if r == 'CreateFile': 
                    index_num = processedData[header[3]][i].rfind('\\') + 1
                    if '.exe' in processedData[header[3]][i][index_num:]: #exclude exe file
                        continue			
			
                    if '.' in processedData[header[3]][i][index_num:]: # remove all folder
                        all_file.append(processedData[header[3]][i][index_num:])
 #           print processedData[header[3]][i]
             #   print all_file[-1]
            
                if (i == first_few_file):
                    break	

#    for i in range(len(all_file)):
#        print all_file[i]
			
            temp_first_msg = []
            temp_first_msg.append(all_file[0])      #insert into temp 	
            all_file.remove(all_file[0])  #remove one record all_file after insert into temp
            temp_num = []
            temp_num.append(1)
            check_count = 0
            range_all_file = len(all_file)


            while 1:   #Search message from the first few file for the message display
                for i in range(range_all_file):
		 
                    if i ==  len(all_file): #Reach the end of the authored loop
                #print 'i : ', i, ' all file  :  ', len(all_file)
                        break
			
                    if i > len(all_file): 
                #print 'i > all file', len(all_file)
                        break
				
                    if temp_first_msg[check_count] == all_file[i]:
                        temp_num[check_count] = temp_num[check_count] + 1 # add one
                        all_file.remove(all_file[i]) # remove the file from all_file

                if len(all_file) == 0:            
                    break
			
        #print '1 end of file  :  ', len(all_file)
                check_count = check_count + 1
                temp_first_msg.append(all_file[0])
                temp_num.append(1)
                all_file.remove(all_file[0])
                range_all_file = len(all_file)
        #print '2 end of file  :  ', len(all_file)
            for i in range(len(temp_num)):
#        print temp[i], temp_num[i]
                if temp_num[i] == max(temp_num):
                    if '.htm' in temp_first_msg[i] or '.txt' in temp_first_msg[i] or '.png' in temp_first_msg[i]:
                        store_msg.append(temp_first_msg[i])
                        for m in range(len(store_msg)): # store the file name in the one variable 
                            temp_first_msg = store_msg[m][store_msg[m].rfind('\\') + 1:]
  #                      print temp
                            msg_file = msg_file + ';' + temp_first_msg
					
                        if len(store_msg) > 0:				
  #                          print 'There are ', len(store_msg), 'file for display message'
                            got_msg = True
                            ransom_note_pos = 1
   #                         print 'Ransomware position: ', ransom_note_pos             
   #                         print store_msg
                            break

            first_few_file = first_few_file + 200
            num_attempt = num_attempt + 1
            if (num_attempt == 3) or (len(store_msg) > 0):
                break
						
    htm = {}
    other = {}
	
    if got_msg == False: #check for msg store at the end. Most 
 #       print 'Step i, 2 and 3 fail. Continue with step 4.'
        for i in range(len(processedData[header[3]]), len(processedData[header[3]])/2):
            if processedData[header[2]] == 'CreateFile':
                temp = processedData[header[3]][processedData[header[3]].rfind('\\'):] 
                if len(htm[temp]) == 0: 
                    if 'HTML' in processedData[header[3]][i]:
                        htm[temp] = 1
                    else:
                        other[temp] = 1				   
                else:		
                    if 'HTML' in processedData[header[3]][i]:
                        htm[temp] = htm[temp] + 1
                    else:
                        other[temp] = other[temp] + 1

                if htm[temp] == 4:
                    store_msg.append(temp)
                    ransom_note_pos = 3
                    msg_file = temp
                    got_msg = True
                    break				
    if got_msg == False: 
 #       print 'There are ', 0, 'file for display message'  
        ransom_note_pos = 0
 #       print 'Ransomware position: ', ransom_note_pos	

    for_record['NumOfMsg']=len(store_msg)
    for_record['MsgFile']= msg_file
    for_record['MsgPos']=ransom_note_pos
    col.append('NumOfMsg')
    col.append('MsgFile')
    col.append('MsgPos')
	
def extractFeatureFromNet(processedData, header, for_record, col):
    network_com = 0
    network_TCP = 'TCP Receive'
    for tcp in processedData[header[2]]:
        if network_TCP in tcp:
            network_com = network_com + 1   
		
    for_record['TCPNetwork'] = network_com
    col.append('TCPNetwork')
	
def generate_MD5(filename, blocksize=65536):

	hash = hashlib.md5()
	
	with open(filename,"rb") as f:
		for block in iter(lambda: f.read(blocksize),b""):
			hash.update(block)
	
	return hash.hexdigest()
	
def VT_scan(file_path):
    API_KEY = '51adb8a913d592891086dc47f5bf627d18056d742f306f67458aa0885b2105ef'

    #sample_MD5 = generate_MD5(file_path)

    vt = VirusTotalPublicApi(API_KEY)

    return vt.get_file_report(sample_MD5)
	
def process_pml_to_csv(procmonexe, pml_file, pmc_file, csv_file):
    """
    Uses Procmon to convert the PML to a CSV file

    Arguments:
        procmonexe: path to Procmon executable
        pml_file: path to Procmon PML output file
        pmc_file: path to PMC filter file
        csv_file: path to output CSV file
    Results:
        None
    """

    print('[*] Converting session to CSV: %s' % csv_file)
    cmdline = '"%s" /OpenLog "%s" /saveas "%s"' % (procmonexe, pml_file, csv_file)
    
    cmdline += ' /LoadConfig "%s"' % pmc_file
    #print('[*] Running cmdline: %s' % cmdline)
    stdnull = subprocess.Popen(cmdline)
    stdnull.wait()

	
	
def main(num, csv_path, pe_name, pe_file):				
#----------------------------------------------------------------------------
    mining_mtrix = {}
    dataset = csv_path
#    print 'Read dataset : ', dataset
    data = pd_read.read_csv(dataset)
    processedData = data.drop(['Time of Day'], axis=1) #, 'TID', 'Image Path', 'Command Line'], axis=1)
    header = []
    global written
    num_of_file = 8

    for h in processedData:
        header.append(h)

    col = [] #column for the dataframe
    for_record = {}
#-------------------------- registry feature---------------------------------------------------------
    status = exractFeatureFromRegistry(processedData, header, for_record, col)
		
#---------------------------------------------Encryption feature ---------------------------------------------------------
    status = extractFeatureFromEncryption(mining_mtrix, processedData, header, for_record, col, '.zip')
    
    format_analysis = ['.doc', '.jpg']
	
    for i in range(len(format_analysis)):
        if status == False:
#            print 'mine ', format_analysis[i]
            mining_mtrix = {}
            status = extractFeatureFromEncryption(mining_mtrix, processedData, header, for_record, col, format_analysis[i], num_of_file)
        else:
            break
	
    if status == False:
#        print 'No encryption feature'
        for_record['EncryptionStep'] = 0
        for_record['EncryptionMin'] = 0
        for_record['EncryptionMax'] = 0
        for_record['EncryptionMean']= 0
        col.append('EncryptionStep')
        col.append('EncryptionMin')
        col.append('EncryptionMax')
        col.append('EncryptionMean')
        for_record['NumOfMsg']=0
        for_record['MsgPos']=0
        col.append('NumOfMsg')
        col.append('MsgPos')
    else:
#------------------------------display_message feature---------------------------------------------------------
        extractFeatureFromMsg(mining_mtrix, processedData, header, for_record, col)
        extractFeatureFromNet(processedData, header, for_record, col)

    csv_file = ''
    head = False
    success_ = False
	
    if status == False:
        csv_file = 'fail.csv'    #Fail attempt
    else:    
        success_ = True
        
    #write to file 
#    print for_record, status
    return for_record, status
		
def findFile(filepath):   
    if os.path.exists(filepath):
        return True
    else:
        return False

def unzip_(zip_file, counter):	
    pe_name = ''
    sel_pe = ''
    dest_dir = ''


        # Create folder
 #   print '\n Recored', counter, zip_file,'\n'
        
    pe_found = False

    zipFile = zip_file[:zip_file.rfind('.')]
 		
    dest_dir = zip_file[:zip_file.rfind('.')]
    pe_name = zip_file[zip_file.rfind('/') + 1 :zip_file.rfind('_')]
 #   print 'zip folder: ', zip_file
 #   print 'pe file: ', pe_name
 #   print 'dest dir:', dest_dir
		
    try:
        zfile = zipfile.ZipFile(zip_file, 'r') # Create ZipFile
    except:
        print 'Bad zip file'
        
    if not os.path.exists(dest_dir):
 #           print 'There is no directory'
        os.makedirs(dest_dir)
         
    elif not os.path.isdir(dest_dir): #If the file is not a directory
 #           print 'This is a file not directory'
        if os.path.exists(dest_dir+ '.bin'): 
            os.remove(dest_dir)
        else:
            os.rename(dest_dir, dest_dir + '.bin') #Rename this file with a format
            if pe_found == False:
                sel_pe =  dest_dir + '.bin' #sel file will be assigned to a newly change file
        os.makedirs(dest_dir)
			
    zfile.extractall(dest_dir)   
			
    for file_name in os.listdir(dest_dir):
            #print 'Filename:   ', file_name
        if ('.csv' in file_name) and ('timeline' not in file_name) and ('Noriben_29_Nov_17__11_03_40_397000' not in file_name):
#            print 'name csv found :', file_name 
					
            temp_file = file_name[file_name.rfind('.'):]
            
#                print 'dest dir: ', dest_dir, '\\', name
 #           shutil.move(zip_file, dest_dir)   #Move file
            result = main(counter, dest_dir+'/'+ file_name, pe_name, sel_pe) 
            break
    return result
				
def dynamic_analysis(file_path, filename):
    counter = 1
    set_first = False
    set_second = False
    results = []
    status = []
 
    print 'file path:', file_path, filename
    while(True):
        for f in os.listdir(file_path):
           # print 'filename:', f
            if not os.path.isdir(file_path + '/' + f):
                if (filename + '_NoribenReport1.zip' in f) and (set_second == False):
                    print 'in zip', f
                    result, stat = unzip_(file_path + '/' + f, counter)
                    counter = counter + 1
                    set_first = True
                    results.append(result), status.append(stat)
                elif (filename + '_NoribenReport2.zip' in f) and (set_first == True):
                    print 'in zip', f
                    result, stat = unzip_(file_path + '/' + f, counter)
                    set_second = True
                    results.append(result), status.append(stat)
        if set_second == True:
            break  
    return results, status

def dynamic_detection(result):
    results = []
    file_path = './classifier1'
    print 'Analysing class'
	
    clf_var = {}
    clf_nor = {}
	
    # Load classifier
    for clf_ml in os.listdir(file_path):
        if os.path.isdir(file_path+'/'+clf_ml):
            continue
        elif 'classifierMinMaxScaler' in clf_ml:
            clf_nor['minmax']=joblib.load(file_path+'/'+clf_ml)
        elif 'classifierPCA' in clf_ml:
            clf_nor['pca']=joblib.load(file_path+'/'+clf_ml)
        elif 'classifier' in clf_ml:
            clf_var[clf_ml]= joblib.load(file_path+'/'+clf_ml)
            print clf_ml
        elif 'feature' in clf_ml:
            features = joblib.load(file_path+'/'+clf_ml)
	

    pe_features = map(lambda x:result[x], features)

    temp = np.reshape(pe_features,(1, len(pe_features)))

    #Normalization
    pe_feature = clf_nor['minmax'].transform(temp)
    pe_feature = clf_nor['pca'].transform(pe_feature)
    
    print 'Normalization completed'
    result = {}
	#predict the sample using the ml model
    print 'Classification finding:'
    for first in clf_var:
        #raw_data = pe_feature[first][fl_second]     #feature heading
        result[first] = clf_var[first].predict(pe_feature)
        results.append(result[first])
        print first[:first.rfind('.')], ':', result[first]

    return results

def ransomware_class(result, dest_ip):
    sample = ''
    if (result == 1):
        sample = 'Cerber'
    elif(result == 2):
        sample = 'Locky'
    elif(result == 3):
        sample = 'Bandarchor'
    elif(result == 4):
        sample = 'Globelmposter'
    elif(result == 5):
        sample = 'Jaff'
    elif(result == 6):
        sample = 'CryptoShield'
    elif(result == 7):
        sample = 'TeslaCrypt'
    elif(result == 8):
        sample = 'Spora'
    elif(result == 9):
        sample = 'WannaCry'
    elif(result == 10):
        sample = 'Gpcoder'
    elif(result == 11):
        sample = 'Eldorado'
    elif(result == 12):
        sample = 'Xorist'
    elif(result == 13):
        sample = 'Filecoder'

    connect_to_client(dest_ip, 'malicious sample is belong to ' + sample + ' class')


if __name__ == "__main__":

    results = []
    create_dir('./allan')
    create_dir('./allan/snortlog')

    stamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')

    os.system('sudo suricata -c /etc/suricata/suricata.yaml -q 0 &')

    path_to_watch = '/var/log/suricata/files'
    print "Watching ", path_to_watch

    before = files_to_timestamp(path_to_watch)
    url_table = {} # This will record the number of redundant url received
    counter = 0 # count number of redundant url
    temp = None


    while 1:

        time.sleep (2)
        after = files_to_timestamp(path_to_watch)

        added = [f for f in after.keys() if not f in before.keys()]


        removed = [f for f in before.keys() if not f in after.keys()]
        modified = []

        for f in before.keys():
            if not f in removed:
                if os.path.getmtime(f) != before.get(f): 
                    modified.append(f)
        if removed: print "Removed: ", ", ".join(removed)
        if modified: print "Modified ", ", ".join(modified)
        if added: 
            initial_time = time.time()
            #print "Added: ", ",", len(added), added
            for added_file in added:
                if 'meta' not in added_file:
                    continue
                #open meta file 
                dest_ip, full_download = open_meta_file(added_file)
                if (temp == None) or (full_download not in url_table): #First record
                    temp = full_download
                    create_dir('./' + dest_ip)
                    url_table[full_download] = 0

                    connect_to_client(dest_ip, 'Download detected. Analyzing download')
                    os.system( "wget -P " + './' + dest_ip + ' ' + full_download)
                    file_name = full_download[full_download.rfind('/')+1:]
                    
                    first_detection = time.time() 
                    print 'The download detection time is ', first_detection - initial_time
                    result = static_detection('./' + dest_ip + '/' + file_name)
                    check_molicious(file_name, result, dest_ip)

                    static_detection_result = time.time()
                    print 'Static detection time:', static_detection_result - first_detection

                    if result == 0:
                        os.system("python NoribenSandbox.py --update --screenshot -t 60 -f " + "./" + dest_ip +"/" + file_name)
                        result, status = dynamic_analysis('./' + dest_ip, file_name[:file_name.rfind('.')])
                        print result, status
                        for i in range(len(status)-1):
                            if status[i] is True:
                                results = dynamic_detection(result[i])
                                ransomware_class(results[0], dest_ip)
                            else:
                                print('This is not a ransomware')
                        dynamic_detection_result = time.time() 
                        print 'Dynamic detection time', dynamic_detection_result - static_detection_result
                        


                elif full_download in url_table:
                    url_table[full_download] = url_table[full_download] + 1
                    #print 'same download'


        before = after

