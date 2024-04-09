from distutils.core import setup, Extension


def main():
	src = [
		"sgeproto_module.c"
	]
	lib_dirs = ["../../../build/lib"]
	include_dirs = ["../../core"]

	setup(
		name="SgeProto",
		version="0.0.1",
		description="Python interface for SgeProto",
		author="hejingsong",
		author_email="240197153@qq.com",
		ext_modules=[
			Extension(
				name="SgeProto",
				sources=src,
				include_dirs=include_dirs,
				library_dirs=lib_dirs,
				libraries=["sgeextproto"]
			)
		]
	)


if __name__ == "__main__":
	main()
