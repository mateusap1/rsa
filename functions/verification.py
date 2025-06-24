import base64, json, hashlib 
from functions.Utils import os2ip, i2osp 
from functions.signature import sha3_hash 

def parse_signed_document(signed_file_path):
    """
    Lê e analisa o conteúdo de um arquivo de assinatura formatado em Base64.
    signed_file_path: Caminho para o arquivo .sig que contém a assinatura.
    
    Retorna um dicionário com os dados da assinatura (assinatura em bytes,
    chave pública (n, e) e algoritmo de hash).
    """
    with open(signed_file_path, 'r') as f:
        encoded_content = f.read()
    
    try:

        # Cria um JSON
        json_bytes = base64.b64decode(encoded_content)
        json_string = json_bytes.decode('utf-8')
        signature_data = json.loads(json_string)

        # Coleta os dados que serão inseridos nele
        hash_algorithm = signature_data.get("hash_algorithm")
        
        public_key_n = int(signature_data.get("public_key_n"))
        public_key_e = int(signature_data.get("public_key_e"))
        public_key_signer = (public_key_n, public_key_e)
        
        signature_b64_from_json = signature_data.get("signature")

        if signature_b64_from_json is None:
            raise ValueError("Chave 'signature' não encontrada no arquivo JSON assinado.")

        signature_bytes = base64.b64decode(signature_b64_from_json)

        return {
            "hash_algorithm": hash_algorithm,
            "public_key_signer": public_key_signer,
            "signature_bytes": signature_bytes
        }

    except (base64.binascii.Error, json.JSONDecodeError, ValueError, TypeError) as e:
        raise ValueError(f"Erro ao analisar o arquivo de assinatura: {e}. O formato pode estar inválido.")

def decrypt_signature_hash(signature_bytes, public_key, expected_hash_byte_length):
    """
    Decifra a assinatura usando a chave pública do signatário.
    signature_bytes: A assinatura em bytes.
    public_key: A chave pública do signatário (n, e).
    expected_hash_byte_length: O comprimento esperado do hash em bytes (ex: 32 para SHA3-256).
    
    Retorna o hash original decifrado em bytes.
    """
    n, e = public_key
    k = (n.bit_length() + 7) // 8

    signature_int = os2ip(signature_bytes)

    if not (0 <= signature_int < n):
        raise ValueError("Assinatura inválida: valor fora do intervalo do módulo [0, n-1].")

    # Calcula o RSA
    decrypted_value_int = pow(signature_int, e, n)
    
    # converte para bytes e ignora o zero padding, 
    # mantendo apenas os ultimos 32 bytes, que são o Hash
    decrypted_full_bytes = i2osp(decrypted_value_int, k)
    decrypted_hash_bytes = decrypted_full_bytes[-expected_hash_byte_length:]
    
    return decrypted_hash_bytes

def verify_signature(original_file_path, signed_file_path):
    """
    Verifica a validade de uma assinatura digital para um arquivo.
    original_file_path: Caminho para o arquivo original (não assinado).
    signed_file_path: Caminho para o arquivo .sig que contém a assinatura.
    
    Retorna True se a assinatura for válida, False caso contrário.
    """

    # Recupera as informações do dict
    signature_info = parse_signed_document(signed_file_path)
        
    signature_bytes = signature_info["signature_bytes"]
    public_key_signer = signature_info["public_key_signer"]
    hash_algorithm_name = signature_info["hash_algorithm"]

    # obtem o tamanho do hash
    try:
        hasher_temp = hashlib.new(hash_algorithm_name)
        expected_hash_len_bytes = hasher_temp.digest_size
    except ValueError:
        raise ValueError(f"Algoritmo de hash '{hash_algorithm_name}' não reconhecido para determinar o tamanho do digest.")

    # obtem o hash do .sig
    decrypted_hash_bytes = decrypt_signature_hash(signature_bytes, public_key_signer, expected_hash_len_bytes)
    print(f"DEBUG: Decrypted hash (bytes): {decrypted_hash_bytes.hex()}")

    # obtem o hash do arquivo original
    actual_file_hash_bytes = sha3_hash(original_file_path, hash_algorithm_name)
    print(f"DEBUG: Actual file hash (bytes): {actual_file_hash_bytes.hex()}")

    # Compara
    if decrypted_hash_bytes == actual_file_hash_bytes:
        print(f"Assinatura válida para o arquivo '{original_file_path}'!")
        return True
    else:
        print(f"Assinatura inválida para o arquivo '{original_file_path}'. Os hashes não correspondem.")
        return False
            
