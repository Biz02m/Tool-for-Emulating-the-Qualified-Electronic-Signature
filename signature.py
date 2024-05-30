import base64
from lxml import etree
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
import os
import time


def verify_signature(signature_xml_path, public_key_path):
    # Wczytanie pliku XML
    with open(signature_xml_path, "rb") as f:
        xml_data = f.read()

    # Parsowanie pliku XML
    root = etree.fromstring(xml_data)

    # Wczytanie podpisu
    signature_value = root.find(".//{http://www.w3.org/2000/09/xmldsig#}SignatureValue").text.strip()
    signature = base64.b64decode(signature_value.encode('utf-8'))

    # Sprawdzenie czy istnieje element EncryptedHash
    encrypted_hash_elem = root.find(".//{http://www.w3.org/2000/09/xmldsig#}EncryptedHash")
    if encrypted_hash_elem is None:
        raise ValueError("Nie znaleziono elementu EncryptedHash")

    # Wczytanie zaszyfrowanego hasha dokumentu
    encrypted_hash = root.find(".//{http://www.w3.org/2000/09/xmldsig#}EncryptedHash").text.strip()
    encrypted_hash_bytes = base64.b64decode(encrypted_hash.encode('utf-8'))

    # Wczytanie informacji o dokumencie
    doc_info = {
        "Size": int(root.find(".//{http://www.w3.org/2000/09/xmldsig#}Size").text.strip()),
        "Extension": root.find(".//{http://www.w3.org/2000/09/xmldsig#}Extension").text.strip(),
        "ModificationDate": root.find(".//{http://www.w3.org/2000/09/xmldsig#}ModificationDate").text.strip(),
    }

    # Wczytanie znacznika czasu
    timestamp = root.find(".//{http://www.w3.org/2000/09/xmldsig#}Timestamp").text.strip()

    # Hashowanie danych
    h = SHA256.new()
    h.update(encrypted_hash_bytes)

    # Wczytanie klucza publicznego
    with open(public_key_path, "rb") as f:
        public_key = RSA.import_key(f.read())

    try:
        pkcs1_15.new(public_key).verify(h, signature)
        print("Podpis cyfrowy jest poprawny.")
        print("Informacje o dokumencie:")
        print("Rozmiar:", doc_info["Size"], "bajtów")
        print("Rozszerzenie:", doc_info["Extension"])
        print("Data modyfikacji:", doc_info["ModificationDate"])
        print("Znacznik czasu podpisu:", timestamp)
    except (ValueError, TypeError):
        print("Podpis cyfrowy jest niepoprawny.")

def sign_file(file_path, private_key_path, user_info, output_xml_path):

    with open(file_path, "rb") as f:
        data = f.read()

    with open(private_key_path, "rb") as f:
        private_key = RSA.import_key(f.read())

    # Hashing data
    h = SHA256.new(data)

    # Signing the data
    signature = pkcs1_15.new(private_key).sign(h)
    signature_base64 = base64.b64encode(signature).decode('utf-8')

    # Create the structure for xml in the desired standard
    root = etree.Element("Signature", xmlns="http://www.w3.org/2000/09/xmldsig#")

    # Information about the document
    doc_info = etree.SubElement(root, "DocumentInfo")
    etree.SubElement(doc_info, "Size").text = str(os.path.getsize(file_path))
    etree.SubElement(doc_info, "Extension").text = os.path.splitext(file_path)[1]
    etree.SubElement(doc_info, "ModificationDate").text = time.ctime(os.path.getmtime(file_path))

    # Information about the user signing the document
    user_info_elem = etree.SubElement(root, "UserInfo")
    etree.SubElement(user_info_elem, "Name").text = user_info.get("name", "")
    etree.SubElement(user_info_elem, "Email").text = user_info.get("email", "")

    signed_info = etree.SubElement(root, "SignedInfo")
    etree.SubElement(signed_info, "CanonicalizationMethod", Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315")
    etree.SubElement(signed_info, "SignatureMethod", Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")

    reference = etree.SubElement(signed_info, "Reference", URI=file_path)
    transforms = etree.SubElement(reference, "Transforms")
    etree.SubElement(transforms, "Transform", Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature")
    digest_method = etree.SubElement(reference, "DigestMethod", Algorithm="http://www.w3.org/2001/04/xmlenc#sha256")
    digest_value = etree.SubElement(reference, "DigestValue")
    digest_value.text = base64.b64encode(h.digest()).decode('utf-8')

    signature_value = etree.SubElement(root, "SignatureValue")
    signature_value.text = signature_base64

    key_info = etree.SubElement(root, "KeyInfo")
    key_value = etree.SubElement(key_info, "KeyValue")
    rsa_key_value = etree.SubElement(key_value, "RSAKeyValue")

    modulus = base64.b64encode(
        private_key.publickey().n.to_bytes((private_key.publickey().n.bit_length() + 7) // 8, 'big')).decode('utf-8')
    exponent = base64.b64encode(
        private_key.publickey().e.to_bytes((private_key.publickey().e.bit_length() + 7) // 8, 'big')).decode('utf-8')

    etree.SubElement(rsa_key_value, "Modulus").text = modulus
    etree.SubElement(rsa_key_value, "Exponent").text = exponent

    # Encrypted hash of the document
    encrypted_hash = base64.b64encode(h.digest()).decode('utf-8')
    encrypted_hash_elem = etree.SubElement(root, "EncryptedHash")
    encrypted_hash_elem.text = encrypted_hash

    timestamp = etree.SubElement(root, "Timestamp")
    timestamp.text = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime())

    tree = etree.ElementTree(root)
    with open(output_xml_path, "wb") as f:
        tree.write(f, pretty_print=True, xml_declaration=True, encoding="UTF-8")


user_info = {
    "name": "Joe Mama",
    "email": "joemama@gmail.pg.edu.com.pl"
}
#sign_file("example.pdf", "private_key.txt", user_info, "signature.xml")
verify_signature("signature.xml", "public_key.txt")