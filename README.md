# Implementação RSA

## Integrantes
Mateus Oliveira Santos - 221029150
Pedro Brum Tristão de Castro - 202067470

O relatório encontra-se no arquivo `Relatorio_Trabalho2_RSA.pdf`. A implementação do RSA bem como do OAEPen contra-se no caderno jupyter `rsa.ipynb` enquanto a assinatura e verificação de documentos encontra-se em `assinatura_verificacao.ipynb` e utiliza funções auxiliares do diretório `functions/`.

Os cadernos jupyter já contém todo o código, no entanto, `main.py` permite, de forma simples, observar o comportamento completo do RSA, desde a geração de chaves, assinatura de documento e verificação.

Toda a implementação foi feita do zero pelos integrantes do grupo, exceto a geração de um número aleatório (não primo), que vem do sistema operacional através da biblioteca `secrets`, e a hash, utilizando a biblioteca hashlib. 