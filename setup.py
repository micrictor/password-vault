from setuptools import setup, find_packages
import pathlib

here = pathlib.Path(__file__).parent.resolve()

# Get the long description from the README file
long_description = (here / 'README.md').read_text(encoding='utf-8')

# Arguments marked as "Required" below must be included for upload to PyPI.
# Fields marked as "Optional" may be commented out.

setup(
    name='password-vault',
    version='1.0.0',
    description='A simple CLI password vault',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/micrictor/password-vault',
    author='Michael R. Torres',  
    author_email='author@example.com',
    package_dir={'': 'src'},
    packages=find_packages(where='src'),
    python_requires='>=3.6, <4',

    # This field lists other packages that your project depends on to run.
    # Any package you put here will be installed by pip when your project is
    # installed, so they must be valid existing projects.
    #
    # For an analysis of "install_requires" vs pip's requirements files see:
    # https://packaging.python.org/en/latest/requirements.html
    install_requires=[
        'astroid>2.5',
        'attrs>20',
        'cffi>1.1',
        'cmd2==1.5.0',
        'colorama==0.4.4',
        'cryptography==3.4.6',
        'isort==5.7.0',
        'lazy-object-proxy==1.5.2',
        'mccabe==0.6.1',
        'passlib==1.7.4',
        'pycparser==2.20',
        'pylint==2.7.2',
        'pyperclip==1.8.2',
        'toml==0.10.2',
        'wcwidth==0.2.5',
        'wrapt==1.12.1',
    ],

    entry_points = {
        "console_scripts": [
            "password-vault = password_vault:main"
        ]
    }
)
