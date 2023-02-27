#include <unicorn/unicorn.h>
#include <capstone/capstone.h>
#include <string.h>
#include <stdint.h>

#define BASE_ADDRESS 0x00000000000a2380
#define STACK_TOP    0x55aa55aa0000fffc
char function[] = {  // glibc-2.34-40.el9.x86_64_libc: __pthread_mutex_lock_full   0x00000000000A2380
	'\x41','\x57','\x41','\x56','\x41','\x55','\x41','\x54','\x55','\x48','\x89','\xfd','\x53','\x48','\x83','\xec',
	'\x28','\x64','\x48','\x8b','\x04','\x25','\x28','\x00','\x00','\x00','\x48','\x89','\x44','\x24','\x18','\x31',
	'\xc0','\x64','\x8b','\x04','\x25','\xd0','\x02','\x00','\x00','\x89','\x44','\x24','\x0c','\x8b','\x57','\x10',
	'\x4c','\x8d','\x77','\x10','\x89','\xd0','\x83','\xe0','\x7f','\x83','\xf8','\x33','\x0f','\x8f','\xd6','\x01',
	'\x00','\x00','\x83','\xf8','\x2f','\x0f','\x8f','\xf5','\x00','\x00','\x00','\x83','\xf8','\x13','\x0f','\x8f',
	'\xe4','\x00','\x00','\x00','\x83','\xe2','\x70','\x0f','\x84','\xab','\x00','\x00','\x00','\x4c','\x8d','\x4f',
	'\x20','\x64','\x4c','\x89','\x0c','\x25','\xf0','\x02','\x00','\x00','\x8b','\x17','\x31','\xc9','\x41','\xbd',
	'\xca','\x00','\x00','\x00','\xbb','\x81','\x08','\x00','\x00','\x85','\xd2','\x0f','\x85','\xe4','\x03','\x00',
	'\x00','\x8b','\x74','\x24','\x0c','\x89','\xd0','\x09','\xce','\xf0','\x0f','\xb1','\x75','\x00','\x89','\xc2',
	'\x85','\xc0','\x0f','\x85','\xcd','\x03','\x00','\x00','\x81','\x7d','\x08','\xfe','\xff','\xff','\x7f','\x0f',
	'\x84','\x0e','\x05','\x00','\x00','\xc7','\x45','\x04','\x01','\x00','\x00','\x00','\x64','\x48','\x8b','\x04',
	'\x25','\xe0','\x02','\x00','\x00','\x48','\x83','\xe0','\xfe','\x4c','\x89','\x48','\xf8','\x64','\x48','\x8b',
	'\x04','\x25','\xe0','\x02','\x00','\x00','\x48','\x89','\x45','\x20','\x64','\x48','\x8b','\x04','\x25','\x10',
	'\x00','\x00','\x00','\x48','\x05','\xe0','\x02','\x00','\x00','\x48','\x89','\x45','\x18','\x64','\x4c','\x89',
	'\x0c','\x25','\xe0','\x02','\x00','\x00','\x64','\x48','\xc7','\x04','\x25','\xf0','\x02','\x00','\x00','\x00',
	'\x00','\x00','\x00','\x8b','\x44','\x24','\x0c','\x83','\x45','\x0c','\x01','\x89','\x45','\x08','\x90','\x45',
	'\x31','\xc0','\xeb','\x0a','\x0f','\x1f','\x40','\x00','\x41','\xb8','\x16','\x00','\x00','\x00','\x48','\x8b',
	'\x44','\x24','\x18','\x64','\x48','\x2b','\x04','\x25','\x28','\x00','\x00','\x00','\x0f','\x85','\x66','\x06',
	'\x00','\x00','\x48','\x83','\xc4','\x28','\x44','\x89','\xc0','\x5b','\x5d','\x41','\x5c','\x41','\x5d','\x41',
	'\x5e','\x41','\x5f','\xc3','\x0f','\x1f','\x40','\x00','\x83','\xe8','\x20','\x83','\xf8','\x03','\x77','\xc8',
	'\x8b','\x45','\x10','\x41','\x89','\xc1','\x41','\x83','\xe1','\x03','\x83','\xe0','\x10','\x41','\x89','\xc0',
	'\x0f','\x85','\xd2','\x01','\x00','\x00','\x8b','\x45','\x00','\x25','\xff','\xff','\xff','\x3f','\x39','\x44',
	'\x24','\x0c','\x0f','\x84','\x13','\x04','\x00','\x00','\x8b','\x5c','\x24','\x0c','\x31','\xc0','\xf0','\x0f',
	'\xb1','\x5d','\x00','\x85','\xc0','\x0f','\x84','\xc3','\x01','\x00','\x00','\xbe','\x06','\x00','\x00','\x00',
	'\x41','\xbd','\x80','\x00','\x00','\x00','\x45','\x85','\xc0','\x0f','\x84','\xd5','\x03','\x00','\x00','\x45',
	'\x31','\xd2','\x31','\xd2','\x48','\x89','\xef','\xb8','\xca','\x00','\x00','\x00','\x0f','\x05','\x83','\xf8',
	'\x92','\x0f','\x84','\x34','\x02','\x00','\x00','\x8d','\x50','\x23','\x83','\xfa','\x23','\x0f','\x87','\x3d',
	'\x01','\x00','\x00','\x48','\xb9','\x01','\x20','\x00','\x81','\x09','\x00','\x00','\x00','\x48','\x0f','\xa3',
	'\xd1','\x0f','\x83','\x29','\x01','\x00','\x00','\x89','\xc2','\x83','\xe2','\xdf','\x83','\xfa','\xdd','\x0f',
	'\x85','\x06','\x02','\x00','\x00','\x83','\xf8','\xdd','\x0f','\x84','\x32','\x03','\x00','\x00','\x83','\xf8',
	'\xfd','\x75','\x09','\x45','\x85','\xc0','\x0f','\x85','\x5e','\x05','\x00','\x00','\x48','\x8d','\x5c','\x24',
	'\x14','\x0f','\x1f','\x80','\x00','\x00','\x00','\x00','\x45','\x89','\xe8','\x31','\xc9','\x31','\xd2','\x31',
	'\xf6','\x48','\x89','\xdf','\xc7','\x44','\x24','\x14','\x00','\x00','\x00','\x00','\xe8','\x4f','\x9e','\xff',
	'\xff','\xeb','\xe5','\x0f','\x1f','\x44','\x00','\x00','\x83','\xe8','\x40','\x83','\xf8','\x03','\x0f','\x87',
	'\xe4','\xfe','\xff','\xff','\x8b','\x47','\x10','\x41','\xbd','\xff','\xff','\xff','\xff','\x44','\x8b','\x27',
	'\x8b','\x5c','\x24','\x0c','\x3b','\x5f','\x08','\x0f','\x84','\x6f','\x01','\x00','\x00','\x41','\xbf','\xca',
	'\x00','\x00','\x00','\x0f','\x1f','\x44','\x00','\x00','\x44','\x89','\xe3','\xc1','\xeb','\x13','\xe8','\x4d',
	'\x57','\x00','\x00','\x39','\xd8','\x0f','\x8f','\x5d','\x02','\x00','\x00','\x89','\xde','\x44','\x89','\xef',
	'\xe8','\x3b','\x53','\x00','\x00','\x41','\x89','\xc0','\x85','\xc0','\x0f','\x85','\x9e','\xfe','\xff','\xff',
	'\x45','\x89','\xe0','\x41','\x81','\xe0','\x00','\x00','\xf8','\xff','\x45','\x89','\xc1','\x44','\x89','\xc0',
	'\x41','\x83','\xc9','\x01','\xf0','\x44','\x0f','\xb1','\x4d','\x00','\x74','\x74','\x44','\x89','\xc2','\x83',
	'\xca','\x02','\xeb','\x0e','\x0f','\x1f','\x40','\x00','\x44','\x89','\xc0','\xf0','\x0f','\xb1','\x55','\x00',
	'\x74','\x5e','\x44','\x89','\xc8','\xf0','\x0f','\xb1','\x55','\x00','\x89','\xc1','\x41','\x89','\xc4','\x81',
	'\xe1','\x00','\x00','\xf8','\xff','\x41','\x39','\xc8','\x75','\x66','\x41','\x39','\xc0','\x74','\xd9','\x41',
	'\x8b','\x36','\x45','\x31','\xd2','\x48','\x89','\xef','\x44','\x89','\xf8','\xf7','\xd6','\x81','\xe6','\x80',
	'\x00','\x00','\x00','\x0f','\x05','\x48','\x3d','\x00','\xf0','\xff','\xff','\x76','\xbb','\x83','\xc0','\x0b',
	'\x83','\xf8','\x0b','\x77','\x0b','\xbf','\x81','\x08','\x00','\x00','\x48','\x0f','\xa3','\xc7','\x72','\xa8',
	'\x48','\x8d','\x3d','\xc1','\xb1','\x11','\x00','\xe8','\x24','\x2f','\xff','\xff','\x0f','\x1f','\x40','\x00',
	'\x8b','\x45','\x08','\x85','\xc0','\x0f','\x85','\x5e','\x04','\x00','\x00','\xc7','\x45','\x04','\x01','\x00',
	'\x00','\x00','\xe9','\xdc','\xfd','\xff','\xff','\x66','\x0f','\x1f','\x84','\x00','\x00','\x00','\x00','\x00',
	'\x41','\x89','\xdd','\xe9','\x20','\xff','\xff','\xff','\x48','\x8d','\x45','\x20','\x48','\x83','\xc8','\x01',
	'\x64','\x48','\x89','\x04','\x25','\xf0','\x02','\x00','\x00','\xe9','\x18','\xfe','\xff','\xff','\x45','\x85',
	'\xc0','\x74','\xc8','\x81','\x7d','\x08','\xfe','\xff','\xff','\x7f','\x0f','\x84','\xb0','\x02','\x00','\x00',
	'\xc7','\x45','\x04','\x01','\x00','\x00','\x00','\x64','\x48','\x8b','\x14','\x25','\xe0','\x02','\x00','\x00',
	'\x48','\x8d','\x45','\x20','\x48','\x83','\xe2','\xfe','\x48','\x89','\x42','\xf8','\x64','\x48','\x8b','\x14',
	'\x25','\xe0','\x02','\x00','\x00','\x48','\x89','\x55','\x20','\x64','\x48','\x8b','\x1c','\x25','\x10','\x00',
	'\x00','\x00','\x48','\x8d','\x93','\xe0','\x02','\x00','\x00','\x48','\x89','\x55','\x18','\x48','\x83','\xc8',
	'\x01','\x64','\x48','\x89','\x04','\x25','\xe0','\x02','\x00','\x00','\x64','\x48','\xc7','\x04','\x25','\xf0',
	'\x02','\x00','\x00','\x00','\x00','\x00','\x00','\xe9','\x47','\xfd','\xff','\xff','\x83','\xe0','\x03','\x83',
	'\xf8','\x02','\x0f','\x84','\xa0','\x02','\x00','\x00','\x83','\xf8','\x01','\x0f','\x85','\x7c','\xfe','\xff',
	'\xff','\x8b','\x47','\x04','\x83','\xf8','\xff','\x0f','\x84','\xdb','\x01','\x00','\x00','\x83','\xc0','\x01',
	'\x45','\x31','\xc0','\x89','\x45','\x04','\xe9','\x33','\xfd','\xff','\xff','\x8b','\x45','\x00','\x25','\x00',
	'\x00','\x00','\x40','\x45','\x85','\xc0','\x0f','\x84','\xf8','\x00','\x00','\x00','\x85','\xc0','\x0f','\x84',
	'\x4f','\xff','\xff','\xff','\xf0','\x81','\x65','\x00','\xff','\xff','\xff','\xbf','\x48','\xb8','\x01','\x00',
	'\x00','\x00','\xff','\xff','\xff','\x7f','\x48','\x89','\x45','\x04','\x64','\x48','\x8b','\x14','\x25','\xe0',
	'\x02','\x00','\x00','\x48','\x8d','\x45','\x20','\x48','\x83','\xe2','\xfe','\x48','\x89','\x42','\xf8','\x64',
	'\x48','\x8b','\x14','\x25','\xe0','\x02','\x00','\x00','\x48','\x89','\x55','\x20','\x64','\x48','\x8b','\x1c',
	'\x25','\x10','\x00','\x00','\x00','\x48','\x8d','\x93','\xe0','\x02','\x00','\x00','\x48','\x89','\x55','\x18',
	'\x48','\x83','\xc8','\x01','\x64','\x48','\x89','\x04','\x25','\xe0','\x02','\x00','\x00','\x64','\x48','\xc7',
	'\x04','\x25','\xf0','\x02','\x00','\x00','\x00','\x00','\x00','\x00','\x41','\xb8','\x82','\x00','\x00','\x00',
	'\xe9','\xa9','\xfc','\xff','\xff','\x41','\x89','\xd0','\x41','\x81','\xe0','\x00','\x00','\x00','\x40','\x0f',
	'\x85','\xcb','\x00','\x00','\x00','\x89','\xd0','\x25','\xff','\xff','\xff','\x3f','\x39','\x44','\x24','\x0c',
	'\x0f','\x84','\x58','\x02','\x00','\x00','\x89','\xd6','\x85','\xd2','\x0f','\x89','\x4e','\x01','\x00','\x00',
	'\x89','\xf2','\x45','\x31','\xd2','\x31','\xf6','\x48','\x89','\xef','\x44','\x89','\xe8','\x0f','\x05','\x48',
	'\x3d','\x00','\xf0','\xff','\xff','\x0f','\x87','\x18','\x02','\x00','\x00','\x8b','\x55','\x00','\xb9','\x00',
	'\x00','\x00','\x80','\xe9','\xc1','\xfb','\xff','\xff','\x41','\xb8','\x16','\x00','\x00','\x00','\x41','\x83',
	'\xfd','\xff','\x0f','\x84','\x46','\xfc','\xff','\xff','\xbe','\xff','\xff','\xff','\xff','\x44','\x89','\xef',
	'\x44','\x89','\x44','\x24','\x0c','\xe8','\xc6','\x50','\x00','\x00','\x44','\x8b','\x44','\x24','\x0c','\xe9',
	'\x2a','\xfc','\xff','\xff','\x85','\xc0','\x0f','\x84','\x1f','\xfe','\xff','\xff','\x48','\x8d','\x0d','\xfd',
	'\xea','\x11','\x00','\xba','\xbb','\x01','\x00','\x00','\x48','\x8d','\x35','\xb2','\x67','\x11','\x00','\x48',
	'\x8d','\x3d','\x1a','\xb1','\x11','\x00','\xe8','\x95','\xb3','\xfa','\xff','\x0f','\x1f','\x44','\x00','\x00',
	'\x41','\x83','\xe9','\x01','\x41','\x83','\xf9','\x01','\x0f','\x87','\xce','\xfc','\xff','\xff','\x48','\x8d',
	'\x0d','\xcb','\xea','\x11','\x00','\xba','\xac','\x01','\x00','\x00','\x48','\x8d','\x35','\x80','\x67','\x11',
	'\x00','\x48','\x8d','\x3d','\x88','\xb0','\x11','\x00','\xe8','\x63','\xb3','\xfa','\xff','\x0f','\x1f','\x00',
	'\x8b','\x44','\x24','\x0c','\x89','\xd6','\x81','\xe6','\x00','\x00','\x00','\x80','\x09','\xc8','\x09','\xc6',
	'\x89','\xd0','\xf0','\x0f','\xb1','\x75','\x00','\x0f','\x84','\x06','\x01','\x00','\x00','\x89','\xc2','\xe9',
	'\x15','\xfb','\xff','\xff','\x44','\x8b','\x6d','\x10','\x41','\x81','\xe5','\x80','\x00','\x00','\x00','\x44',
	'\x89','\xee','\x40','\x80','\xf6','\x86','\xe9','\x14','\xfc','\xff','\xff','\x41','\x83','\xf9','\x02','\x0f',
	'\x84','\xad','\x01','\x00','\x00','\x41','\x83','\xf9','\x01','\x0f','\x85','\xd9','\xfb','\xff','\xff','\x64',
	'\x48','\xc7','\x04','\x25','\xf0','\x02','\x00','\x00','\x00','\x00','\x00','\x00','\x8b','\x45','\x04','\x83',
	'\xf8','\xff','\x0f','\x85','\x25','\xfe','\xff','\xff','\x41','\xb8','\x0b','\x00','\x00','\x00','\xe9','\x5b',
	'\xfb','\xff','\xff','\xc7','\x45','\x04','\x00','\x00','\x00','\x00','\x87','\x55','\x00','\x83','\xfa','\x01',
	'\x0f','\x8f','\x5a','\x01','\x00','\x00','\x64','\x48','\xc7','\x04','\x25','\xf0','\x02','\x00','\x00','\x00',
	'\x00','\x00','\x00','\x41','\xb8','\x83','\x00','\x00','\x00','\xe9','\x30','\xfb','\xff','\xff','\x81','\xce',
	'\x00','\x00','\x00','\x80','\x89','\xd0','\xf0','\x0f','\xb1','\x75','\x00','\x0f','\x84','\x9f','\xfe','\xff',
	'\xff','\x8b','\x55','\x00','\xe9','\x80','\xfa','\xff','\xff','\x0f','\x1f','\x80','\x00','\x00','\x00','\x00',
	'\xc7','\x45','\x04','\x00','\x00','\x00','\x00','\x45','\x31','\xd2','\x31','\xd2','\x48','\x89','\xef','\xbe',
	'\x07','\x00','\x00','\x00','\xb8','\xca','\x00','\x00','\x00','\x0f','\x05','\x48','\x3d','\x00','\xf0','\xff',
	'\xff','\x76','\xa3','\x83','\xf8','\x92','\x74','\x9e','\x83','\xc0','\x26','\x83','\xf8','\x26','\x0f','\x87',
	'\xbc','\xfc','\xff','\xff','\x48','\xba','\x09','\x00','\x00','\x08','\x6c','\x00','\x00','\x00','\x89','\xc1',
	'\x48','\xd3','\xea','\x80','\xe2','\x01','\x0f','\x84','\xa4','\xfc','\xff','\xff','\xe9','\x75','\xff','\xff',
	'\xff','\x0f','\x1f','\x80','\x00','\x00','\x00','\x00','\x41','\xb8','\x23','\x00','\x00','\x00','\xe9','\xab',
	'\xfa','\xff','\xff','\x48','\xb8','\x01','\x00','\x00','\x00','\xff','\xff','\xff','\x7f','\x48','\x89','\x45',
	'\x04','\x64','\x48','\x8b','\x04','\x25','\xe0','\x02','\x00','\x00','\x48','\x83','\xe0','\xfe','\x4c','\x89',
	'\x48','\xf8','\x64','\x48','\x8b','\x04','\x25','\xe0','\x02','\x00','\x00','\x48','\x89','\x45','\x20','\x64',
	'\x48','\x8b','\x04','\x25','\x10','\x00','\x00','\x00','\x48','\x05','\xe0','\x02','\x00','\x00','\x48','\x89',
	'\x45','\x18','\x64','\x4c','\x89','\x0c','\x25','\xe0','\x02','\x00','\x00','\x64','\x48','\xc7','\x04','\x25',
	'\xf0','\x02','\x00','\x00','\x00','\x00','\x00','\x00','\x41','\xb8','\x82','\x00','\x00','\x00','\xe9','\x4b',
	'\xfa','\xff','\xff','\x83','\xc0','\x0b','\x83','\xf8','\x0b','\x0f','\x87','\x21','\xfc','\xff','\xff','\x48',
	'\x0f','\xa3','\xc3','\x0f','\x83','\x17','\xfc','\xff','\xff','\xe9','\xcd','\xfd','\xff','\xff','\x41','\x8b',
	'\x06','\x83','\xe0','\x7f','\x83','\xf8','\x12','\x74','\x49','\x83','\xf8','\x11','\x0f','\x85','\x94','\xfd',
	'\xff','\xff','\x64','\x48','\xc7','\x04','\x25','\xf0','\x02','\x00','\x00','\x00','\x00','\x00','\x00','\x8b',
	'\x45','\x04','\x83','\xf8','\xff','\x0f','\x84','\x9d','\xfe','\xff','\xff','\x83','\xc0','\x01','\x89','\x45',
	'\x04','\xe9','\xf8','\xf9','\xff','\xff','\x66','\x2e','\x0f','\x1f','\x84','\x00','\x00','\x00','\x00','\x00',
	'\xbe','\x80','\x00','\x00','\x00','\x48','\x89','\xef','\xe8','\x13','\x9b','\xff','\xff','\xe9','\x94','\xfe',
	'\xff','\xff','\x64','\x48','\xc7','\x04','\x25','\xf0','\x02','\x00','\x00','\x00','\x00','\x00','\x00','\x41',
	'\xb8','\x23','\x00','\x00','\x00','\xe9','\xc4','\xf9','\xff','\xff','\x48','\x8d','\x0d','\x9f','\xe8','\x11',
	'\x00','\xba','\xb1','\x01','\x00','\x00','\x48','\x8d','\x35','\x54','\x65','\x11','\x00','\x48','\x8d','\x3d',
	'\x62','\x65','\x11','\x00','\xe8','\x37','\xb1','\xfa','\xff','\x48','\x8d','\x0d','\x80','\xe8','\x11','\x00',
	'\xba','\x4e','\x02','\x00','\x00','\x48','\x8d','\x35','\x35','\x65','\x11','\x00','\x48','\x8d','\x3d','\x59',
	'\x65','\x11','\x00','\xe8','\x18','\xb1','\xfa','\xff'
	};
	uint64_t prec_pc;
	char *coverage_map;


static bool hook_mem_invalid(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data) {
	switch (type) {
	default:
		printf(">>> Missing memory is being READ at 0x%08lx data size = %u\n", address, size);
		printf(">>> allocate 64k at 0x%08lx\n", address & 0xffffffffffff0000);
		uc_mem_map(uc, address & 0xffffffffffff0000, 64 * 1024, UC_PROT_ALL);
		return true;
	case UC_MEM_WRITE_UNMAPPED:
		printf(">>> Missing memory is being WRITE at 0x%08lx data size = %u, data value = 0x%08lx\n", address, size, value);
		printf(">>> allocate 64k at 0x%08lx\n", address & 0xffffffffffff0000);
		uc_mem_map(uc, address & 0xffffffffffff0000, 64 * 1024, UC_PROT_ALL);
		return true;
	}
}

static bool hook_instruction(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data) {
	uint64_t pc;
	int i;

	uc_reg_read(uc, UC_X86_REG_RIP, &pc);
	printf("executed 0x%08lx\n", pc);
	return true;
}
static void  hook_mem_fetch_check(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data) {
	int i;

	printf("]] read at 0x%08lx\n", address);
	if ((address >=BASE_ADDRESS) && (address<=BASE_ADDRESS + sizeof(function) - 1)) {
		for (i=address; i<address+size; i++){
			*(coverage_map+address-BASE_ADDRESS)=1;
			}
		}
}

static void hook_block(uc_engine *uc, uint64_t address, uint32_t size, void *user_data) {
	uint64_t pc,i;
	csh handle;
	cs_insn *insn;
	size_t count;

	if (((address >= BASE_ADDRESS) && (address <= BASE_ADDRESS + sizeof(function) - 1))) {
		if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) uc_emu_stop(uc);
		cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
		count = cs_disasm(handle, (uint8_t *) (function+(address-BASE_ADDRESS)), size, address, 0, &insn);
		if (count > 0) {
			size_t j;
			for (j = 0; j < count; j++) {
				printf("0x%08lx\n",insn[j].detail);
				printf("0x%"PRIx64":\t%s\t\t%s grp:%d,%d,%d,%d\n", insn[j].address, insn[j].mnemonic, insn[j].op_str, 
					insn[j].detail->groups[0],
					insn[j].detail->groups[1],
					insn[j].detail->groups[2],
					insn[j].detail->groups[3]
					);
				}
			cs_free(insn, count);
			}
		cs_close(&handle);
		uc_reg_read(uc, UC_X86_REG_RIP, &pc);
        	printf("block at 0x%08lx size=0x%x   [current pc=0x%08lx]\n", address, size, pc);
		if ((address >= BASE_ADDRESS) && (address <= BASE_ADDRESS + sizeof(function) - 1)) {
			for (i=address; i<address+size; i++) *(coverage_map+i-BASE_ADDRESS)=1;
			}
		} else uc_emu_stop(uc);

}


int main(int argc, char **argv, char **envp) {
	uc_engine *uc;
	uc_err err;
	uc_hook trace1, trace2, trace3;
	uint64_t reg;
	int i;
	bool started=false;

	printf("===================================\n");
	printf("initializing coverage map\n");
	coverage_map =(char *)malloc(sizeof(function));
	memset(coverage_map, 0, sizeof(function));

	err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
	if (err) {
		printf("Failed on uc_open() with error returned: %u\n", err);
		return 1;
		}
	printf("2MB allocating at 0x%08x to host the code\n", BASE_ADDRESS&(4*1024-1));
	uc_mem_map(uc, 0x000a0000, 2 * 1024 * 1024, UC_PROT_ALL);

	// allocate 64k stack
	printf("64KB allocating at 0x%08lx and set stack register at 0x%08lx\n", STACK_TOP & 0xffffffffffff0000, STACK_TOP);
	uc_mem_map(uc, STACK_TOP & 0xffffffffffff0000, 64 * 1024, UC_PROT_ALL);
	reg=STACK_TOP;
	uc_reg_write(uc, UC_X86_REG_RSP, &reg);


	printf("writing function at 0x%08x for %ld bytes\n", BASE_ADDRESS,sizeof(function));
	if (uc_mem_write(uc, BASE_ADDRESS, function, sizeof(function))) {
		printf("Failed to write emulation code to memory, quit!\n");
		return 1;
		}

	printf("Add hook on memory unmapped events\n");
	uc_hook_add(uc, &trace1, UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, hook_mem_invalid, NULL, 1, 0);

//	printf("Add hook on single instruction\n");
//	err=uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_instruction, NULL, 1, 0);
//	printf("UC_HOOK_CODE, -> %d\n", err);
//	err=uc_hook_add(uc, &trace3, UC_HOOK_MEM_READ, hook_mem_fetch_check, NULL, BASE_ADDRESS, BASE_ADDRESS + sizeof(function) - 1);
//	printf("UC_HOOK_MEM_READ -> %d\n", err);

	uc_hook_add(uc, &trace1, UC_HOOK_BLOCK, hook_block, NULL, 1, 0);

	err = uc_emu_start(uc, BASE_ADDRESS, BASE_ADDRESS + sizeof(function) - 1, 0, 0);
	if (err) {
		printf("Failed on uc_emu_start() with error returned %u: %s\n", err, uc_strerror(err));
		}

	printf(">>> Emulation done. Below is the CPU context\n");

	uc_reg_read(uc, UC_X86_REG_RAX, &reg);
	printf(">>> RAX = 0x%lx\n", reg);
	uc_reg_read(uc, UC_X86_REG_RBX, &reg);
	printf(">>> RBX = 0x%lx\n", reg);
	uc_reg_read(uc, UC_X86_REG_RCX, &reg);
	printf(">>> RCX = 0x%lx\n", reg);
	uc_reg_read(uc, UC_X86_REG_RDX, &reg);
	printf(">>> RDX = 0x%lx\n", reg);
	uc_reg_read(uc, UC_X86_REG_RSI, &reg);
	printf(">>> RSI = 0x%lx\n", reg);
	uc_reg_read(uc, UC_X86_REG_RDI, &reg);
	printf(">>> RDI = 0x%lx\n", reg);
	uc_reg_read(uc, UC_X86_REG_R8, &reg);
	printf(">>> R8 = 0x%lx\n", reg);
	uc_reg_read(uc, UC_X86_REG_R9, &reg);
	printf(">>> R9 = 0x%lx\n", reg);
	uc_reg_read(uc, UC_X86_REG_R10, &reg);
	printf(">>> R10 = 0x%lx\n", reg);
	uc_reg_read(uc, UC_X86_REG_R11, &reg);
	printf(">>> R11 = 0x%lx\n", reg);
	uc_reg_read(uc, UC_X86_REG_R12, &reg);
	printf(">>> R12 = 0x%lx\n", reg);
	uc_reg_read(uc, UC_X86_REG_R13, &reg);
	printf(">>> R13 = 0x%lx\n", reg);
	uc_reg_read(uc, UC_X86_REG_R14, &reg);
	printf(">>> R14 = 0x%lx\n", reg);
	uc_reg_read(uc, UC_X86_REG_R15, &reg);
	printf(">>> R15 = 0x%lx\n", reg);
	uc_reg_read(uc, UC_X86_REG_RSP, &reg);
	printf(">>> RSP = 0x%lx\n", reg);
	uc_reg_read(uc, UC_X86_REG_RIP, &reg);
	printf(">>> RIP = 0x%lx\n", reg);
	printf("code coverage map\n");
	for (i=0; i<sizeof(function) - 1; i++) printf("%d", *(coverage_map+i));
	printf("\n");


	uc_close(uc);
}
