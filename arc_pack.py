import os
import struct
import zlib


def not_folder(cn):
    try:
        if not os.path.exists(cn):
            os.mkdir(cn)
    except:
        return '../new_Script\\'
    return cn
def list_all_files(root):
    """递归列出所有文件（含子文件夹）"""
    all_files = []
    for base, dirs, files in os.walk(root):
        for f in files:
            all_files.append(os.path.join(base, f))
    return all_files

def singe_xor(data, key):
    d = b''
    for i in range(len(data)):
        d = d + struct.pack('B', data[i] ^ key[i % 1])
    return d


def vlkyrie_complex_v0_text_en(data):
    d = b''
    for i in data:
        i0 = i
        i = 0xfe - i
        if i > 0:
            d = d + struct.pack('B', i)
        else:
            d = d + i0
    return d


def vlkyrie_complex_v1_text_en(data, key):
    d = b''
    if not key or key == b'\x00':
        return data
    for i in range(len(data)):
        j = (data[i] + 1) ^ key[i % len(key)]
        if j > 0xff:
            j = data[i]
        d = d + struct.pack('B', j)
    return d


def rot_right(byte, bits):
    """对单个字节右旋指定的位数"""
    return (byte >> bits) | ((byte << (8 - bits)) & 0xFF)


def RPM(cn, msg,oldarc,newarc):
    def get_key(key1):
        key1 = key1.decode('CP932')
        for i in range(1, len(key1)):
            k2 = ''.join(key1[0:i])
            k3 = key1.split(k2)
            if k3[1] == '':
                return k2
    def guess_key(msg_path,oldarc):
        keys = []
        try:
            ft = open(msg_path + 'test', 'rb')
            d = ft.read(4)
            filecount = struct.unpack('<I', d)[0]
            ft.read(4)
            print('文件数', filecount)
        except:
            f = open(msg_path+oldarc, 'rb')
            b = f.read()
            f.close()
            f = open(msg_path + 'test', 'wb')
            f.write(b)
            f.close()
            ft = open(msg_path + 'test', 'rb')
            d = ft.read(4)
            ft.read(4)
            filecount = struct.unpack('<I', d)[0]
            print('文件数', filecount)
        filename = []
        for i in range((filecount)):
            filename.append(ft.read(20))
            name = ft.read(12)
            n = []
            for j in range(len(name)):
                x = (0 - name[j]) & 0xff
                x = struct.pack('B', x)
                try:
                    n.append(x.decode('CP932'))
                except:
                    n.append(b'\x00'.decode('CP932'))
            n = ''.join(n)
            if n not in keys:
                keys.append(n)
            else:
                keys.append(n)
            ft.read(12)
        ft.close()
        true_key = []
        for key in keys:
            key = key.encode('CP932')
            name = []
            name0 = filename[0]
            for i in range(len(key)):
                j = (name0[i] + key[i]) & 0xff
                name.append(struct.pack('B', j))
            try:
                a = (b''.join(name).decode('CP932'))
                if key not in true_key:
                    true_key.append(key)
            except:
                continue
        for key in true_key:
            key = get_key(key)
        print('key = '+ key)
        return key
    key = guess_key(msg,oldarc)
    cn = not_folder(cn)
    key = key.encode('CP932')
    files = os.listdir(cn)
    filecount = len(files)
    f = open(msg + newarc, 'wb')
    f.write(struct.pack('i', filecount))
    f.write(b'\x00' * 4)
    pos = 8 + filecount * 44
    data = b''
    for file in files:
        size = os.stat(cn + file).st_size
        data = data + struct.pack(f'{32}s', file.encode('CP932'))
        data = data + struct.pack('i', size)
        data = data + struct.pack('i', size)
        data = data + struct.pack('i', pos)
        pos = pos + size
    pos = 0
    for b in data:
        b = (b - key[pos % len(key)]) & 0xFF
        pos = pos + 1
        b = struct.pack('B', b)
        f.write(b)
    for file in files:
        f1 = open(cn + file, 'rb')
        b = f1.read()
        f1.close()
        f.write(b)
    f.close()


# RPM('E:\Program Files (x86)\Ciel\フォルト！！Ｓ\CN\\','E:\Program Files (x86)\Ciel\フォルト！！Ｓ\\','msg.arc','MSG.cn_')
def FPK_32(cn, msg):
    newarc = 'data.cn_'
    cn = not_folder(cn)
    files = os.listdir(cn)
    filecount = len(files)
    print(hex(filecount))
    f = open(msg + newarc, 'wb')
    c = 0
    f.write(struct.pack('I', filecount + c))
    pos = 4 + filecount * 32
    data = b''
    for file in files:
        size = os.stat(cn + file).st_size
        data = data + struct.pack('i', pos)
        data = data + struct.pack('i', size)
        data = data + struct.pack(f'{24}s', file.encode('cp932'))
        pos = pos + size
    f.write(data)
    for file in files:
        f1 = open(cn + file, 'rb')
        b = f1.read()
        f1.close()
        f.write(b)
    f.close()


# FPK_32('E:\Program Files (x86)\インターハート\Dechauyo\CN\\','E:\Program Files (x86)\インターハート\Dechauyo\\')
def FPK_36(cn, msg):
    oldarc = 'data.fpk'
    newarc = 'data.cn_'
    en = False
    cn = not_folder(cn)

    def from_bytes(a: bytes):
        return int.from_bytes(a, byteorder='little')

    def name():
        f = open(msg + oldarc, 'rb')
        b = f.read()
        f.close()
        f = open(msg + '1', 'wb')
        key = b[-8:-4]
        indexpos = from_bytes(b[-4:])
        x = 0x80000000
        filecount = from_bytes(b[0:4]) - x
        print(filecount)
        print(key)
        b = b[indexpos:indexpos + filecount * 36]
        for i in range(len(b)):
            x = b[i]
            x = x ^ (key[i % 4])
            f.write(struct.pack('B', x))
        f.close()

    name()
    files = os.listdir(cn)
    filecount = len(files)
    print(hex(filecount))
    f = open(msg + newarc, 'wb')
    c = 0X80000000
    print(hex((c + filecount)))
    f.write(struct.pack('I', filecount + c))
    pos = 4 + filecount * 36
    print(hex(pos))
    data = b''
    f1 = open(msg + '1', 'rb')
    fs = len(files) * [b'\x00']
    key = bytes.fromhex('F2 1B B2 5F')
    for i in range(len(files)):
        f1.read(8)
        files[i] = f1.read(24).decode('CP932')
        files[i] = files[i].replace('\x00', '')
        fs[i] = f1.read(4)
    f1.close()
    i = 0
    for file in files:
        size = os.stat(cn + file).st_size
        data = data + struct.pack('i', pos)
        data = data + struct.pack('i', size)
        data = data + struct.pack(f'{24}s', file.encode('CP932'))
        data = data + fs[i]
        # data = data + b'\x00'*4
        i = i + 1
        pos = pos + size
    pos = 0
    if en:
        for i in range(len(data)):
            d = data[i] ^ key[i % len(key)]
            d = struct.pack('B', d)
            f.write(d)
    else:
        f.write(data)
    for file in files:
        f1 = open(cn + file, 'rb')
        b = f1.read()
        f1.close()
        f.write(b)
    if en:
        f.write(key)  # 加密文件名
    else:
        f.write(b'\x00' * 4)  # 不加密文件名
    f.write(struct.pack('i', 4))  # 索引位置
    f.close()


# FPK_36('E:\Program Files (x86)\インターハート\Dechauyo\CN\\','E:\Program Files (x86)\インターハート\Dechauyo\\')
def will_v0(folder, newarcfolder, newarc):
    folder = not_folder(folder)
    files = os.listdir(folder)
    filecount = len(files)
    if not newarc:
        newarc = 'rio.cn_'
    f = open(newarcfolder + newarc, 'wb')
    h = bytes.fromhex('01 00 00 00 53 43 52 00')
    f.write(h)
    f.write(struct.pack('i', filecount))
    h = bytes.fromhex('10 00 00 00')
    f.write(h)
    pos = 16 + filecount * 17
    data = b''
    for file in files:
        size = os.stat(folder + file).st_size
        file = file.replace('.scr', '').upper()
        data = data + struct.pack(f'{9}s', file.encode('cp932'))
        data = data + struct.pack('i', size)
        data = data + struct.pack('i', pos)
        pos = pos + size + 0
    f.write(data)
    for file in files:
        f1 = open(folder + file, 'rb')
        b = f1.read()
        f1.close()
        for a in b:
            a = rot_right(a, 6)
            a = struct.pack('B', a)
            f.write(a)

    f.close()


# will_v0('E:\Program Files (x86)\WillPlus\LoveSplit\Rio\\','E:\Program Files (x86)\WillPlus\LoveSplit\\','')
def yatagarasu(cn, msg, oldarc, newarc):
    def get_key(msg,oldarc):
        fo = open(msg+oldarc, 'rb')
        b = fo.read(0x10C + 4)
        fo.close()
        key = b[0x84:0x84 + 4]
        key2 = b[0x10C:0x10C + 4]
        if key2 != key:
            return ''
        return key
    cn = not_folder(cn)
    files = os.listdir(cn)
    filecount = len(files)
    key = get_key(msg,oldarc)
    if key:
        if type(key) != bytes:
            key = bytes.fromhex(key)
        f = open(msg + newarc, 'wb')
    else:
        key = []
    f = open(msg+newarc, 'wb')
    f.write(struct.pack('I', 0))
    pos = 8 + filecount * 136 + 4
    data = b'' + struct.pack('I', filecount)
    j = 0
    for file in files:
        size = os.stat(cn + file).st_size
        data = data + struct.pack(f'{128}s', file.encode('cp932'))
        data = data + struct.pack('i', size)
        data = data + struct.pack('i', pos)
        pos = pos + size
    data = data + b'\x00' * 4
    if key:
        for i in range(len(data)):
            e = data[i] ^ key[j % len(key)]
            f.write(struct.pack('B', e))
            j = j + 1
    else:
        f.write(data)
    for file in files:
        f1 = open(cn + file, 'rb')
        b = f1.read()
        f1.close()
        j = 0
        if key:
            data = b
            for i in range(len(data)):
                e = data[i] ^ key[j % len(key)]
                f.write(struct.pack('B', e))
                j = j + 1
        else:
            f.write(b)
    f.seek(0)
    data = struct.pack('i', pos)
    j = 0
    if key:
        for i in range(len(data)):
            e = data[i] ^ key[j % len(key)]
            f.write(struct.pack('B', e))
            j = j + 1
    else:
        f.write(data)
    f.close()


# yatagarasu(r'E:\Program Files (x86)\yatagarasu\闇夜に踊れDATA\11\010\\',r'E:\Program Files (x86)\yatagarasu\闇夜に踊れDATA\11\\','yamiP101_010.pkg','yamiP101_010_new.pkg')
def yatagarasu_v2(cn, msg, key, newarc):
    pass


def cdpa_SCR(cn, msg, newarc):
    cn = not_folder(cn)
    files = os.listdir(cn)
    if not newarc:
        newarc = 'CN_'
    fw = open(msg + newarc, 'wb')
    fw.write(b'\x50\x41\x43\x4B')
    filecont = len(files)
    fw.write(struct.pack('i', filecont))
    filestart = len(files) * 40 + 8
    pos = filestart
    for file in files:
        filename = struct.pack(f'{32}s', file.encode('CP932'))
        filesize = os.stat(cn + file).st_size
        filepos = pos
        pos = pos + filesize
        fw.write(filename)
        fw.write(struct.pack('i', filesize))
        fw.write(struct.pack('i', filepos))
    for file in files:
        f = open(cn + file, 'rb')
        data = f.read()
        for b in data:
            b = b ^ 0x80
            fw.write(struct.pack('B', b))
        f.close()
    fw.close()


# cdpa_SCR('E:\Program Files (x86)\CDPA\Silhouette\cn\\','E:\Program Files (x86)\CDPA\Silhouette\\','')
def vlkyrie_complex_v0(cn_path, newarc_path, newarc, key):
    archead = b'File Pack 1.00'
    un = b'\x00'  # 应该是与加密有关
    files = os.listdir(cn_path)
    filecount = len(files)
    pos = 24 + filecount * 40
    f = open(newarc_path + newarc, 'wb')
    f.write(archead)
    f.write(un)
    if not key:
        key = b'\x00'
    else:
        try:
            if type(key) != bytes:
                key = bytes.fromhex(key)
        except:
            key = b'\x00'
    f.write(key)
    data = struct.pack('i', filecount)
    d = singe_xor(data, key)
    f.write(d)  # 写入文件数
    f.write(b'\x00' * 4)  # 用于记录文件总大小 0x14
    f.write(b'\x00' * filecount * 40)
    for i in range(len(files)):
        file = files[i]
        size = os.stat(cn_path + file).st_size
        fcs = open(cn_path + file, 'rb')
        b = fcs.read()
        fcs.close()
        file = struct.pack(f'{32}s', file.encode('CP932'))
        f.write(vlkyrie_complex_v0_text_en(b))
        indexpos = 24 + i * 40
        f.seek(indexpos)
        f.write(singe_xor(file, key))
        f.write(singe_xor(struct.pack('I', pos), key))
        f.write(singe_xor(struct.pack('I', size), key))
        pos = pos + size
        f.seek(pos)
    f.seek(0x14)
    f.write(singe_xor(struct.pack('I', pos), key))


# vlkyrie_complex_v0('E:\Program Files\CIRCUS\KUJIRA_DVD\cn\\', 'E:\Program Files\CIRCUS\KUJIRA_DVD\\', 'Script.tes', 'AA')
def vlkyrie_complex_v1(cn_path, newarc_path, newarc, key1, key2):
    archead = struct.pack(f'{24}s', 'ＶＣ製品版'.encode('CP932'))
    files = os.listdir(cn_path)
    filecount = len(files)
    pos = 24 + filecount * 40
    f = open(newarc_path + newarc, 'wb')
    f.write(archead)
    if not key1:
        key1 = b'\x00'
    else:
        try:
            if type(key1) != bytes:
                key1 = bytes.fromhex(key1)
        except:
            key1 = b'\x00'
    if not key2:
        key2 = b'\x00'
    else:
        try:
            if type(key2) != bytes:
                key2 = bytes.fromhex(key2)
        except:
            key2 = b'\x00'
    data = singe_xor(struct.pack('I', filecount), key1)
    fileinfo = b'\x00' * 4  # 0X1C
    data = data + fileinfo
    size1 = filecount * 16
    data = data + size1 * b'\x00'
    filename_info_index = 0x20
    f.write(data)
    filenamepos = filecount * 16 + 32
    for i in range(len(files)):
        filelen = len(files[i]) + 1
        f.seek(filename_info_index + i * 16)
        f.write(singe_xor(struct.pack('I', 0), key1))
        f.write(singe_xor(struct.pack('I', filelen - 1), key1))
        f.seek(filenamepos)
        f.write(singe_xor(struct.pack(f'{filelen}s', files[i].encode('CP932')), key1))
        filenamepos = filenamepos + filelen
    f.seek(0x1C)
    f.write(singe_xor(struct.pack('I', filenamepos - 0x1C - 4), key1))
    size_pos_index = 0x28
    pos = filenamepos
    f.seek(filenamepos)
    for i in range(len(files)):
        fcs = open(cn_path + files[i], 'rb')
        f.write(vlkyrie_complex_v1_text_en(fcs.read(), key2))
        fcs.close()
        f.seek(size_pos_index + i * 16)
        size = os.stat(cn_path + files[i]).st_size
        f.write(singe_xor(struct.pack('I', pos), key1))
        f.write(singe_xor(struct.pack('I', size), key1))
        pos = pos + size
        f.seek(pos)
    f.close()


# vlkyrie_complex_v1('E:\Program Files\CIRCUS\VC\cn\\', 'E:\Program Files\CIRCUS\VC\\', 'Script.tes', '58','24')
def BGI(cn_path, newarc_path, newarc):
    archead = B'PackFile    '
    files = os.listdir(cn_path)
    filecount = len(files)
    f = open(newarc_path + newarc, 'wb')
    f.write(archead)
    f.write(struct.pack('I', filecount))
    f.write(struct.pack(f'{filecount * 32}s', ''.encode('CP932')))
    fileindex_pos = 16
    pos = 0
    pos1 = filecount * 32 + 16
    for i in range(len(files)):
        size = os.stat(cn_path + files[i]).st_size
        fin = open(cn_path + files[i], 'rb')
        f.write(fin.read())
        fin.close()
        f.seek(fileindex_pos + 32 * i)
        f.write(struct.pack(f'{16}s', files[i].encode('CP932')))
        f.write(struct.pack('I', pos))
        f.write(struct.pack('I', size))
        pos = pos + size
        f.seek(pos + pos1)


# BGI(R'E:\Program Files (x86)\AUGUST\Eyoku no eustia\UserData\\', r'E:\Program Files (x86)\AUGUST\Eyoku no eustia\\', 'A.ARC')
def BGI_V2(cn_path, newarc_path, newarc):
    archead = B'BURIKO ARC20'
    files = os.listdir(cn_path)
    filecount = len(files)
    f = open(newarc_path + newarc, 'wb')
    f.write(archead)
    f.write(struct.pack('I', filecount))
    f.write(struct.pack(f'{filecount * 128}s', ''.encode('CP932')))
    fileindex_pos = 16
    pos = 0
    pos1 = filecount * 128 + 16
    for i in range(len(files)):
        size = os.stat(cn_path + files[i]).st_size
        fin = open(cn_path + files[i], 'rb')
        f.write(fin.read())
        fin.close()
        f.seek(fileindex_pos + 128 * i)
        f.write(struct.pack(f'{96}s', files[i].encode('CP932')))
        f.write(struct.pack('I', pos))
        f.write(struct.pack('I', size))
        pos = pos + size
        f.seek(pos + pos1)
# BGI_V2(R'E:\Program Files (x86)\Citrus\黄昏のフォルクローレ\14B\\', r'E:\Program Files (x86)\Citrus\黄昏のフォルクローレ\\', 'A.ARC')
def seraphim(cn_path, newarc_path, newarc):
    def zlib_compress(data: bytes) -> bytes:
        """
        对传入的原始数据进行zlib压缩（适用于Seraphim封包/解包）。
        返回压缩后的bytes，zlib头默认78 9C。
        """
        return zlib.compress(data)

    # 用法举例：
    # with open('00000.bin', 'rb') as f:
    #     raw = f.read()
    # compressed = zlib_compress(raw)
    # with open('00000.z', 'wb') as f:
    #     f.write(compressed)
    archead = B''
    files = os.listdir(cn_path)
    filecount = len(files)
    f = open(newarc_path + newarc, 'wb')
    f.write(archead)
    f.write(struct.pack('I', filecount))
    f.write(struct.pack(f'{(filecount + 1) * 4}s', ''.encode('CP932')))
    fileindex_pos = 8
    pos = (filecount + 1) * 4 + 4
    print(hex(pos))
    f.seek(4)
    f.write(struct.pack('I', pos))
    f.seek((filecount + 1) * 4+4)
    posbuf = []
    for i in range(len(files)):
        fin = open(cn_path + files[i], 'rb')
        b = zlib_compress(fin.read())
        size = len(b)
        pos = pos + size
        posbuf.append(struct.pack('I', pos))
        f.write(b)
        fin.close()
    f.seek(8)
    f.write(b''.join(posbuf))


# seraphim('E:\Program Files (x86)\CARMINE\ANOTHER\CN\\', 'E:\Program Files (x86)\CARMINE\ANOTHER\\', 'ScnPac.Dat')

def unity_SHIROKURO(cn_path, newarc_path, newarc):
    def gettime():
        import time

        # 获取当前时间的时间戳
        current_timestamp = time.time()

        # 将时间戳转换为本地时间
        local_time = time.localtime(current_timestamp)

        # 格式化时间
        formatted_time = time.strftime('%Y-%m-%d %H:%M:%S', local_time)
        print(formatted_time)
        return formatted_time

    archead = b'@ARCH000\x0e'
    files = list_all_files(cn_path)
    fin = open(newarc_path + newarc, 'wb')
    fin.write(archead)
    timetext = gettime().replace(' ', '').replace('-', '').replace(':', '')
    timelen = len(timetext)
    fin.write(struct.pack(f'{timelen}s', timetext.encode('UTF8')))
    pos = 0x17
    data = []
    data.append(struct.pack('I', len(files)))
    # exit()
    un = B'\x00'
    for i in range(len(files)):
        sp = files[i].split('\\')
        folder = '/' + '/'.join(sp[1:-1])
        file = sp[-1]
        f = open(files[i], 'rb')
        b = f.read()
        f.close()
        szie = len(b)
        if folder == '/':
            folder = ''
            folderlen = b''
        else:
            folderlen = struct.pack('B', len(folder.encode('UTF8')))
        filelen = len(file.encode('UTF8'))
        folderlen1 = len(folder.encode('UTF8'))
        data.append(B''
                    + folderlen
                    + struct.pack(f'{folderlen1}s', folder.encode('UTF8'))
                    + struct.pack('B', filelen)
                    + struct.pack(f'{filelen}s', file.encode('UTF8'))
                    + struct.pack('I', pos)
                    + struct.pack('I', 0)
                    + struct.pack('I', szie)
                    + struct.pack('I', 0)
                    + b'\x4E'
                    + un
                    )
        fin.write(b)
        pos = pos + szie
        un = b''
    data.append(folderlen + struct.pack(f'{folderlen1}s', folder.encode('UTF8')))
    data.append(struct.pack('I', pos) + struct.pack('I', 0))
    fin.write(b''.join(data))
    fin.close()
    print(hex(pos))

# unity_SHIROKURO('./unpack\\', './\\', 'base_div0_archive.arc')
