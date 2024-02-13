#ifndef _CBUF_H
#define _CBUF_H

#include <stdint.h>


struct _cbuf
{
    uint8_t *data;
    int data_len;

    int head;
    int tail;
};



int InitCBuf( struct _cbuf *cbuf, int len );

void FreeCBuf( struct _cbuf *cbuf );

// returns # of bytes waiting in cbuf
int CheckCBuf( struct _cbuf *cbuf );

void AddByteToCBuf( struct _cbuf *cbuf, uint8_t Data);

// add len bytes from Data[] to cbuf
void AddDataToCBuf( struct _cbuf *cbuf, uint8_t *Data, int len );

// returns -1 if no data available, or returns one byte from cbuf
int GetByteFromCBuf( struct _cbuf *cbuf );

// returns -1 if fewer than len bytes are available
// returns # of bytes read
int GetDataFromCBuf( struct _cbuf *cbuf, uint8_t *data, int len, int timeout );

// add len bytes from data[] to beginning of cbuf
int StuffDataInCBuf( struct _cbuf *cbuf, uint8_t *data, int len );


#endif  // _CBUF_H
