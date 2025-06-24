from functions.signature import sha3_hash, sign_message_hash, format_signature_output
from functions.verification import verify_signature
from functions.keygen import generate_rsa_keys


with open("documento.txt", "w") as f:
    f.write("Este e um documento de teste para assinatura.")

public_key_signer, private_key_signer = generate_rsa_keys(bits=1024,show=True)

file_to_sign = "documento.txt" 

message_hash_bytes = sha3_hash(file_to_sign)
print(f"\nHash do documento ({len(message_hash_bytes)} bytes): {message_hash_bytes.hex()}")

# 4. Assinar o hash
signature_bytes = sign_message_hash(message_hash_bytes, private_key_signer)

# 5. Formatar o resultado para salvar
signed_document_content = format_signature_output(signature_bytes, public_key_signer, "SHA3-256")

# 6. Salvar o resultado em um arquivo (por exemplo, "documento.txt.sig")
with open(file_to_sign + ".sig", "w") as f:
    f.write(signed_document_content)



###########################################################################################



original_doc = "documento.txt"
signed_doc_file = "documento.txt.sig"

print("\n--- Iniciando Verificação ---")
is_valid = verify_signature(original_doc, signed_doc_file)

if is_valid:
    print("Verificação concluída com sucesso: Assinatura é autêntica.")
else:
    print("Verificação concluída: Assinatura não é autêntica ou foi adulterada.")

print()
print()

# Teste de adulteração (opcional):
# Altere o arquivo original e tente verificar novamente
with open("documento.txt", "a") as f:
    f.write(".")
print("\n--- Tentando verificar após adulteração do arquivo original ---")
is_valid_after_tamper = verify_signature(original_doc, signed_doc_file)
if not is_valid_after_tamper:
    print("Adulteração detectada com sucesso (como esperado).")