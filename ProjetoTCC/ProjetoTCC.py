# -*- coding: utf-8 -*-
# Projeto: Diego Rodrigues Cardoso
# Março, 2021

import json
import csv
import sys
import os

class Product(object):
	def __str__(self):
		#define o formato do produto no csv
		return '{0}:{1}:{2}'.format(self.company, self.product, self.version)

# extrai campos do cpe
def parse_cpe(cpe):
	#cpe:2.3:o:google:android:7.2:*:*:*:*:*:*:*
	fields = cpe.split(':')
	obj = Product()
	obj.company = fields[3]
	obj.product = fields[4]
	obj.version = fields[5]
	return obj

# verifica se é dispositivo mobile
def is_mobile_product(products):
	result = False
	for o in products:
		if  (o.company == 'google' and o.product == 'android' and o.version == '11.0'):
                   #(o.company == 'apple' and o.product == 'iphone_os'): #or\
                   #(o.company == 'google' and o.product == 'android' and o.version == '7.1.2') or\
		   return True

# obtem lista simples de produtos afetados
def get_products(configurations):
	result = []
	for n in configurations['nodes']:
		if not n.get('cpe_match'):
			continue
		for m in n['cpe_match']:
			if m['vulnerable'] == True:
				result.append(parse_cpe(m['cpe23Uri']))
	return result

is_file_exists = os.path.exists('dados.csv')
csv = open('dados.csv', 'a')
if not is_file_exists:
       csv.write('ID;CVSSv3;Severity;Attack;Problemtype;Description;publishedDate;lastModifiedDate;Products;\n')#cabeçalho das colunas
qtdp = 0
qtd = 0

# abre arquivo passado como parâmetro
if len(sys.argv) < 2:
	print("Passe o arquivo json como parâmetro.")
else:
	arquivo = sys.argv[1]
	print("Carregando arquivo {0} ...".format(arquivo))
	jsonf = open(arquivo, 'r')
	data = json.load(jsonf)
	for entry in data['CVE_Items']:
		qtdp += 1
		#print('.')
	
		products = get_products(entry['configurations'])
		if is_mobile_product(products):
			cve = entry['cve']
			qtd += 1
			fields = [
				cve['CVE_data_meta']['ID'],

                                entry['impact']['baseMetricV3']['cvssV3']['baseScore'],
                                entry['impact']['baseMetricV3']['cvssV3']['baseSeverity'],
                                entry['impact']['baseMetricV3']['cvssV3']['attackVector'],

                                cve['problemtype']['problemtype_data'][0]['description'][0]['value'],
				cve['description']['description_data'][0]['value'],
                                
                                entry['publishedDate'],
                                entry['lastModifiedDate'],
				*products,	
			]
                        
			csv.write(';'.join(str(f) for f in fields))
			csv.write('\n')

	csv.close()
	print('Sucesso. Processados: {0}, Retornados: {1}'.format(qtdp, qtd))
