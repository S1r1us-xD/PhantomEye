from setuptools import setup, find_packages

setup(
    name="phantomeye",
    version="2.0.0",
    author="S1r1us",
    description="PhantomEye — Hybrid Network & Web Vulnerability Assessment Framework",
    long_description=open("README.md").read() if __import__("os").path.exists("README.md") else "",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[
        "requests>=2.28.0",
        "urllib3>=1.26.0",
    ],
    entry_points={
        "console_scripts": [
            "pe=phantomeye:main",
            "phantomeye=phantomeye:main",
        ]
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: POSIX :: Linux",
        "Topic :: Security",
        "Environment :: Console",
    ],
)
