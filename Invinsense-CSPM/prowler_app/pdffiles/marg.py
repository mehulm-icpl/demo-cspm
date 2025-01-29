from PyPDF2 import PdfMerger

def meargFile(file1,file2):
    pdfs = [file1,file2]

    merger = PdfMerger()

    for pdf in pdfs:
        merger.append(pdf)

    merger.write("C:/Users/vekar/PycharmProjects/prowler_dynamic/prowler_app/pdffiles/result.pdf")
    merger.close()
    return 'data was appentded'

def call():
    meargFile('C:/Users/vekar/PycharmProjects/prowler_dynamic/prowler_app/pdffiles/nayan.pdf','C:/Users/vekar/PycharmProjects/prowler_dynamic/prowler_app/pdffiles/about_page.pdf')
    return 'function was called the pdf was mearg'