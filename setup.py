from setuptools import setup, find_packages

setup(
    name="calsync",
    version="1",
    packages=find_packages(),
    entry_points={
        "console_scripts": ["calsync = calsync:main"]
        },
    install_requires=[
        'icalendar==6.0.1',
        'requests>=2.24.0',
        'click==8.1.3'
        ]
    )
