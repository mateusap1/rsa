import hashlib, json, base64
from functions.Utils import os2ip, i2osp 

def sha3_hash(filepath, hash_algo='sha3-256'):
    """
    Calcula o hash SHA-3 de um arquivo.
    filepath: Caminho para o arquivo a ser hasheado.
    hash_algo: O algoritmo SHA-3 a ser usado (ex: 'sha3-256', 'sha3-512').
    
    Retorna os bytes do hash (digest).
    """
    try:
        hasher = hashlib.new(hash_algo)
    except ValueError:
        raise ValueError(f"Algoritmo de hash '{hash_algo}' não suportado ou inválido.")

    with open(filepath, 'rb') as f:
        while True:
            chunk = f.read(4096)
            if not chunk:
                break
            hasher.update(chunk)
    
    return hasher.digest()

def sign_message_hash(message_hash_bytes, private_key):
    """
    Assina o hash de uma mensagem usando a chave privada RSA.
    message_hash_bytes: O hash da mensagem em bytes (ex: resultado de calculate_sha3_hash).
    private_key: A chave privada do signatário (n, d).
    
    Retorna a assinatura em bytes.
    """

    n, d = private_key
    k = (n.bit_length() + 7) // 8 


    hash_int = os2ip(message_hash_bytes)

    signature_int = pow(hash_int, d, n)
    
    signature_bytes = i2osp(signature_int, k)
    
    return signature_bytes

def format_signature_output(signature_bytes, public_key_signer, hash_algorithm_name):
    """
    Formata a assinatura e informações para verificação em um string Base64.
    signature_bytes: A assinatura em bytes (resultado de sign_message_hash).
    public_key_signer: A chave pública do signatário (n, e).
    hash_algorithm_name: O nome do algoritmo de hash usado (ex: "SHA3-256").
    
    Retorna uma string Base64.
    """
    n_signer, e_signer = public_key_signer

    n_str = str(n_signer)
    e_str = str(e_signer)
    
    signature_b64 = base64.b64encode(signature_bytes).decode('utf-8')

    signature_data = {
        "hash_algorithm": hash_algorithm_name,
        "public_key_n": n_str,
        "public_key_e": e_str,
        "signature": signature_b64
    }

    json_string = json.dumps(signature_data, indent=2)
    json_bytes = json_string.encode('utf-8')
    final_b64_string = base64.b64encode(json_bytes).decode('utf-8')

    return final_b64_string