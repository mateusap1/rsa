import secrets

def generate_random_number(bits):
    
    if bits < 2:
        raise ValueError("O número de bits deve ser no mínimo 2.")

    num = secrets.randbits(bits)

    num |= (1 << (bits - 1))
    num |= 1
    return num

def miller_rabin_test(n, k=40):
    """
    Implementa o teste de primalidade de Miller-Rabin.
    n: o número a ser testado.
    k: o número de iterações (precisão do teste).
    """
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True   
    if n % 2 == 0:
        return False  

    s = 0
    d = n - 1
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(k):

        a = secrets.randbelow(n - 3) + 2 
        x = pow(a, d, n) 

        if x == 1 or x == n - 1:
            continue 

        is_composite = True
        for _ in range(s - 1):
            x = pow(x, 2, n) 
            if x == n - 1:
                is_composite = False
                break
        
        if is_composite:
            return False

    return True 

def generate_prime_number(bits):
    """
    Gera um número primo com o número especificado de bits usando Miller-Rabin.
    """
    while True:
        p = generate_random_number(bits)
        if miller_rabin_test(p):
            return p

def generate_rsa_keys(bits=1024, show=False):
    """
    Gera as chaves públicas e privadas RSA.
    bits: número de bits para p e q (mínimo 1024).
    """
    if show:
        print(f"Gerando p (primo de {bits} bits)...")
    
    p = generate_prime_number(bits)
    
    if show:
        print(f"p gerado: {p}")

    if show:
        print(f"Gerando q (primo de {bits} bits)...")
    # Garante que p e q sejam diferentes
    q = generate_prime_number(bits)
    while q == p:
        q = generate_prime_number(bits)
    
    if show:
        print(f"q gerado: {q}")


    n = p * q
    phi_n = (p - 1) * (q - 1)

    e = 65537 
    while gcd(e, phi_n) != 1: 
        e = secrets.randbelow(phi_n - 2) + 2 

    
    d = modular_inverse(e, phi_n) 

    return (n, e), (n, d) 


def gcd(a, b):
    """Calcula o Maior Divisor Comum (MDC) usando o algoritmo de Euclides."""
    while b:
        a, b = b, a % b
    return a

def extended_gcd(a, b):
    """
    Algoritmo Euclidiano Estendido para encontrar gcd(a, b) e x, y tal que ax + by = gcd(a, b).
    Usado para encontrar o inverso modular.
    """
    if a == 0:
        return b, 0, 1
    else:
        g, y, x = extended_gcd(b % a, a)
        return g, x - (b // a) * y, y

def modular_inverse(a, m):
    """
    Calcula o inverso modular de a mod m usando o algoritmo Euclidiano Estendido.
    a * x = 1 (mod m)
    """
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise Exception('O inverso modular não existe')
    else:
        return x % m


if __name__ == "__main__":
    public_key, private_key = generate_rsa_keys(bits=1024)
    print("\nChave Pública (n, e):", public_key)
    print("Chave Privada (n, d):", private_key)