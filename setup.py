from setuptools import setup

setup(
    name='xmfaxencryptor',
    version='1.0.0',
    description='The xmfaxencryptor Python module for XM Fax',
    long_description='See https://github.com/xmedius/xmfaxencryptor for more information',
    url='https://github.com/xmedius/xmfaxencryptor-python/',
    author='XMedius R&D',
    license='MIT',
    classifiers=[
        'Programming Language :: Python :: 3.7'
    ],
    packages=['xmfaxencryptor'],
    install_requires=['cryptography'],
)
