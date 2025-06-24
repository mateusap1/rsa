import hashlib

def i2osp(x, xlen):
    """
    Integer-to-Octet-String Primitive (RFC 8017, Section 4.1)
    Converte um inteiro não negativo x em uma string de octetos de comprimento xlen.
    """
    if not isinstance(x, int) or x < 0:
        raise TypeError("x deve ser um inteiro não negativo.")
    if not isinstance(xlen, int) or xlen < 0:
        raise TypeError("xlen deve ser um inteiro não negativo.")
    
    # x.to_bytes() requer um tamanho. Se x for muito grande para xlen, ele falhará.
    # Se x for muito pequeno, ele preencherá com zeros à esquerda.
    return x.to_bytes(xlen, 'big')

def os2ip(x):
    """
    Octet-String-to-Integer Primitive (RFC 8017, Section 4.2)
    Converte uma string de octetos x em um inteiro não negativo.
    """
    if not isinstance(x, bytes):
        raise TypeError("x deve ser uma string de octetos (bytes).")
    return int.from_bytes(x, 'big')

def mgf1(mgfSeed, maskLen, H):
    """
    Mask Generation Function 1 (MGF1) conforme PKCS#1 v2.2 (RFC 8017, Section B.2.1).
    H é a função hash a ser usada (e.g., hashlib.sha256).
    """
    if not isinstance(mgfSeed, bytes):
        raise TypeError("mgfSeed deve ser bytes.")
    if not isinstance(maskLen, int) or maskLen < 0:
        raise TypeError("maskLen deve ser um inteiro não negativo.")
    if not hasattr(H, 'digest_size'):
        raise TypeError("H deve ser um objeto hash com atributo digest_size.")

    hLen = H.digest_size
    if maskLen > (2**32) * hLen:
        raise ValueError("maskLen é muito grande.")

    T = b""
    for counter in range(0, (maskLen + hLen - 1) // hLen):
        C = counter.to_bytes(4, 'big') 
        T += H(mgfSeed + C).digest()
    
    return T[:maskLen]

